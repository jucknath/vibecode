#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/XKBlib.h>
#include <X11/keysym.h>
#include <security/pam_appl.h>
#include <unistd.h>
#include <pwd.h>

#include <X11/extensions/XInput2.h>
#include <X11/extensions/Xinerama.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cerrno>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <iostream>
#include <limits.h>
#include <linux/input.h>
#include <linux/vt.h>
#include <mutex>
#include <optional>
#include <poll.h>
#include <queue>
#include <string>
#include <sys/ioctl.h>
#include <sys/inotify.h>
#include <vector>
#include <thread>

namespace {

constexpr const char *kEvdevEnvVar = "VIBELOCK_EVDEV_GRAB";
constexpr size_t kBitsPerLong = sizeof(unsigned long) * 8;
constexpr size_t kEvBitArraySize = (EV_MAX / kBitsPerLong) + 1;
constexpr size_t kKeyBitArraySize = (KEY_MAX / kBitsPerLong) + 1;
constexpr size_t kMaxPasswordLength = 32;
constexpr const char kBlockingMessage[] = "Error. Blocking for 5 seconds";
constexpr std::chrono::seconds kBlockingDuration(5);

struct RawKeyEvent {
    int code{-1};
    int value{0};  // 0 = release, 1 = press, 2 = repeat
};

bool testBit(const unsigned long *array, size_t size, int bit) {
    if (!array || bit < 0) {
        return false;
    }
    size_t idx = static_cast<size_t>(bit) / kBitsPerLong;
    if (idx >= size) {
        return false;
    }
    unsigned long mask = 1UL << (static_cast<size_t>(bit) % kBitsPerLong);
    return (array[idx] & mask) != 0;
}

class EvdevGrabber {
public:
    ~EvdevGrabber() {
        shutdown();
    }

    bool initialize() {
        setupDeviceWatch();
        if (!discoverKeyboards()) {
            shutdown();
            return false;
        }
        stopRequested.store(false);
        worker = std::thread(&EvdevGrabber::readerLoop, this);
        active = true;
        return true;
    }

    void shutdown() {
        stopRequested.store(true);
        if (worker.joinable()) {
            worker.join();
        }
        closeAllDevices();
        if (inputWatch >= 0 && inotifyFd >= 0) {
            inotify_rm_watch(inotifyFd, inputWatch);
        }
        inputWatch = -1;
        if (inotifyFd >= 0) {
            close(inotifyFd);
            inotifyFd = -1;
        }
        {
            std::lock_guard<std::mutex> lock(queueMutex);
            std::queue<RawKeyEvent> empty;
            std::swap(events, empty);
        }
        active = false;
    }

    bool popEvent(RawKeyEvent &ev, int timeoutMs) {
        std::unique_lock<std::mutex> lock(queueMutex);
        if (!queueCond.wait_for(lock, std::chrono::milliseconds(timeoutMs),
                                [&]() { return !events.empty() || stopRequested.load(); })) {
            return false;
        }
        if (events.empty()) {
            return false;
        }
        ev = events.front();
        events.pop();
        return true;
    }

    bool isActive() const {
        if (!active) {
            return false;
        }
        std::lock_guard<std::mutex> lock(deviceMutex);
        return !devices.empty();
    }

private:
    bool isInputDevice(int fd) {
        std::array<unsigned long, kEvBitArraySize> evBits{};
        if (ioctl(fd, EVIOCGBIT(0, sizeof(evBits)), evBits.data()) < 0) {
            return false;
        }
        if (!testBit(evBits.data(), evBits.size(), EV_KEY)) {
            return false;
        }

        std::array<unsigned long, kKeyBitArraySize> keyBits{};
        if (ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(keyBits)), keyBits.data()) < 0) {
            return false;
        }

        auto hasAnyKey = [&](const std::initializer_list<int> &keys) -> bool {
            for (int key : keys) {
                if (testBit(keyBits.data(), keyBits.size(), key)) {
                    return true;
                }
            }
            return false;
        };

        // Accept both regular keyboards and media/consumer keyboards so they cannot bypass the grab.
        const bool keyboardKeys =
            hasAnyKey({KEY_A, KEY_Q, KEY_Z, KEY_1, KEY_ENTER, KEY_SPACE, KEY_LEFTCTRL});
        const bool mediaKeys = hasAnyKey({KEY_PLAYPAUSE, KEY_STOPCD, KEY_NEXTSONG, KEY_PREVIOUSSONG, KEY_MUTE,
                                          KEY_VOLUMEUP, KEY_VOLUMEDOWN, KEY_HOMEPAGE, KEY_REFRESH, KEY_SEARCH});
        const bool powerKeys = hasAnyKey({KEY_POWER, KEY_POWER2, KEY_SLEEP, KEY_SUSPEND, KEY_WAKEUP});
        const bool pointerButtons =
            hasAnyKey({BTN_LEFT, BTN_RIGHT, BTN_MIDDLE, BTN_SIDE, BTN_EXTRA, BTN_FORWARD, BTN_BACK, BTN_TASK});
        const bool touchButtons =
            hasAnyKey({BTN_TOUCH, BTN_TOOL_FINGER, BTN_TOOL_DOUBLETAP, BTN_TOOL_TRIPLETAP, BTN_TOOL_QUADTAP});
        const bool stylusButtons =
            hasAnyKey({BTN_TOOL_PEN, BTN_TOOL_RUBBER, BTN_STYLUS, BTN_STYLUS2, BTN_STYLUS3});
        const bool hasAbs = testBit(evBits.data(), evBits.size(), EV_ABS);
        const bool hasRel = testBit(evBits.data(), evBits.size(), EV_REL);
        const bool pointerLike = (pointerButtons && (hasAbs || hasRel)) ||
                                 (touchButtons && hasAbs) ||
                                 (stylusButtons && hasAbs);

        return keyboardKeys || mediaKeys || powerKeys || pointerLike;
    }

    bool addDevice(const std::string &path) {
        std::lock_guard<std::mutex> lock(deviceMutex);
        return addDeviceLocked(path);
    }

    bool discoverKeyboards() {
        DIR *dir = opendir("/dev/input");
        if (!dir) {
            return false;
        }
        struct dirent *entry = nullptr;
        bool added = false;
        while ((entry = readdir(dir)) != nullptr) {
            if (std::strncmp(entry->d_name, "event", 5) != 0) {
                continue;
            }
            std::string path = std::string("/dev/input/") + entry->d_name;
            if (addDevice(path)) {
                added = true;
            }
        }
        closedir(dir);
        return added;
    }

    void readerLoop() {
        std::vector<pollfd> pollFds;
        while (!stopRequested.load()) {
            buildPollList(pollFds);
            if (pollFds.empty()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }

            int ret = poll(pollFds.data(), pollFds.size(), 100);
            if (ret < 0) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }
            if (ret == 0) {
                continue;
            }
            for (pollfd &pfd : pollFds) {
                if (!(pfd.revents & (POLLIN | POLLERR | POLLHUP))) {
                    continue;
                }
                if (pfd.fd == inotifyFd) {
                    handleInotifyEvents();
                    continue;
                }
                if (pfd.revents & POLLIN) {
                    processDeviceEvents(pfd.fd);
                }
                if (pfd.revents & (POLLERR | POLLHUP)) {
                    removeDeviceByFd(pfd.fd);
                }
            }
        }
    }

    struct Device {
        int fd{-1};
        std::string path;
    };

    std::vector<Device> devices;
    std::thread worker;
    mutable std::mutex deviceMutex;
    int inotifyFd{-1};
    int inputWatch{-1};

    std::mutex queueMutex;
    std::condition_variable queueCond;
    std::queue<RawKeyEvent> events;
    std::atomic<bool> stopRequested{false};
    bool active{false};

    bool addDeviceLocked(const std::string &path) {
        for (const auto &device : devices) {
            if (device.path == path) {
                return true;
            }
        }
        int fd = open(path.c_str(), O_RDONLY | O_NONBLOCK);
        if (fd < 0) {
            return false;
        }
        if (!isInputDevice(fd)) {
            close(fd);
            return false;
        }
        if (ioctl(fd, EVIOCGRAB, 1) < 0) {
            close(fd);
            return false;
        }
        devices.push_back(Device{fd, path});
        return true;
    }

    void removeDeviceByFd(int fd) {
        std::lock_guard<std::mutex> lock(deviceMutex);
        auto it = std::find_if(devices.begin(), devices.end(),
                               [&](const Device &dev) { return dev.fd == fd; });
        if (it != devices.end()) {
            releaseDevice(*it);
            devices.erase(it);
        }
    }

    void removeDeviceByPath(const std::string &path) {
        std::lock_guard<std::mutex> lock(deviceMutex);
        auto it = std::find_if(devices.begin(), devices.end(),
                               [&](const Device &dev) { return dev.path == path; });
        if (it != devices.end()) {
            releaseDevice(*it);
            devices.erase(it);
        }
    }

    void releaseDevice(Device &device) {
        if (device.fd >= 0) {
            ioctl(device.fd, EVIOCGRAB, 0);
            close(device.fd);
            device.fd = -1;
        }
    }

    void closeAllDevices() {
        std::lock_guard<std::mutex> lock(deviceMutex);
        for (auto &device : devices) {
            releaseDevice(device);
        }
        devices.clear();
    }

    void buildPollList(std::vector<pollfd> &pollFds) {
        pollFds.clear();
        if (inotifyFd >= 0) {
            pollfd watch{};
            watch.fd = inotifyFd;
            watch.events = POLLIN;
            pollFds.push_back(watch);
        }
        std::lock_guard<std::mutex> lock(deviceMutex);
        for (const auto &device : devices) {
            if (device.fd < 0) {
                continue;
            }
            pollfd pfd{};
            pfd.fd = device.fd;
            pfd.events = POLLIN;
            pollFds.push_back(pfd);
        }
    }

    void processDeviceEvents(int fd) {
        input_event evBuffer[64];
        ssize_t bytes = read(fd, evBuffer, sizeof(evBuffer));
        if (bytes <= 0) {
            if (bytes < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                return;
            }
            removeDeviceByFd(fd);
            return;
        }
        size_t count = static_cast<size_t>(bytes) / sizeof(input_event);
        for (size_t e = 0; e < count; ++e) {
            if (evBuffer[e].type == EV_KEY) {
                RawKeyEvent ev;
                ev.code = static_cast<int>(evBuffer[e].code);
                ev.value = static_cast<int>(evBuffer[e].value);
                {
                    std::lock_guard<std::mutex> lock(queueMutex);
                    events.push(ev);
                }
                queueCond.notify_one();
            }
        }
    }

    void handleInotifyEvents() {
        if (inotifyFd < 0) {
            return;
        }
        alignas(struct inotify_event) char buffer[4096];
        while (true) {
            ssize_t bytes = read(inotifyFd, buffer, sizeof(buffer));
            if (bytes <= 0) {
                if (bytes < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    break;
                }
                return;
            }
            size_t offset = 0;
            while (offset < static_cast<size_t>(bytes)) {
                auto *event = reinterpret_cast<struct inotify_event *>(buffer + offset);
                if (event->len > 0) {
                    std::string name(event->name);
                    if (std::strncmp(name.c_str(), "event", 5) == 0) {
                        std::string path = std::string("/dev/input/") + name;
                        if (event->mask & (IN_CREATE | IN_ATTRIB | IN_MOVED_TO)) {
                            addDevice(path);
                        } else if (event->mask & (IN_DELETE | IN_MOVED_FROM | IN_DELETE_SELF)) {
                            removeDeviceByPath(path);
                        }
                    }
                }
                offset += sizeof(struct inotify_event) + event->len;
            }
        }
    }

    void setupDeviceWatch() {
        inotifyFd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        if (inotifyFd < 0) {
            std::cerr << "vibelock: warning: unable to initialize inotify for /dev/input" << std::endl;
            return;
        }
        inputWatch = inotify_add_watch(
            inotifyFd,
            "/dev/input",
            IN_CREATE | IN_ATTRIB | IN_MOVED_TO | IN_DELETE | IN_MOVED_FROM);
        if (inputWatch < 0) {
            std::cerr << "vibelock: warning: unable to add /dev/input watch for hotplug keyboards" << std::endl;
            close(inotifyFd);
            inotifyFd = -1;
        }
    }
};

std::string trimWhitespace(const std::string &input) {
    size_t start = 0;
    while (start < input.size() && std::isspace(static_cast<unsigned char>(input[start]))) {
        ++start;
    }
    if (start == input.size()) {
        return "";
    }
    size_t end = input.size();
    while (end > start && std::isspace(static_cast<unsigned char>(input[end - 1]))) {
        --end;
    }
    return input.substr(start, end - start);
}

std::string runCommand(const std::string &cmd) {
    std::string output;
    FILE *pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        return output;
    }
    char buffer[128];
    while (fgets(buffer, sizeof(buffer), pipe)) {
        output.append(buffer);
    }
    pclose(pipe);
    return output;
}

bool ensureSleepInhibition(int argc, char **argv) {
    if (std::getenv("VIBELOCK_INHIBITED")) {
        return true;
    }

    std::array<char, PATH_MAX> exePath{};
    ssize_t len = readlink("/proc/self/exe", exePath.data(), exePath.size() - 1);
    if (len <= 0) {
        std::cerr << "vibelock: warning: unable to resolve executable path for systemd-inhibit" << std::endl;
        return false;
    }
    exePath[static_cast<size_t>(len)] = '\0';

    std::vector<char *> args;
    args.push_back(const_cast<char *>("systemd-inhibit"));
    args.push_back(const_cast<char *>("--what=sleep"));
    args.push_back(const_cast<char *>("--who=vibelock"));
    args.push_back(const_cast<char *>("--why=screen lock active"));
    args.push_back(const_cast<char *>("--mode=block"));
    args.push_back(exePath.data());
    for (int i = 1; i < argc; ++i) {
        args.push_back(argv[i]);
    }
    args.push_back(nullptr);

    if (setenv("VIBELOCK_INHIBITED", "1", 1) != 0) {
        std::cerr << "vibelock: warning: unable to set inhibitor flag: " << std::strerror(errno) << std::endl;
        return false;
    }

    execvp("systemd-inhibit", args.data());
    std::cerr << "vibelock: warning: failed to exec systemd-inhibit: " << std::strerror(errno) << std::endl;
    unsetenv("VIBELOCK_INHIBITED");
    return false;
}

std::string getSettingValue(const std::string &schema, const std::string &key) {
    if (schema.empty() || key.empty()) {
        return "";
    }
    return trimWhitespace(runCommand("gsettings get " + schema + " " + key + " 2>/dev/null"));
}

bool setSettingValue(const std::string &schema, const std::string &key, const std::string &value) {
    if (schema.empty() || key.empty() || value.empty()) {
        return false;
    }
    std::string command = "gsettings set " + schema + " " + key + " \"" + value + "\" >/dev/null 2>&1";
    return std::system(command.c_str()) == 0;
}

std::string getOverlayKey() {
    return getSettingValue("org.gnome.mutter", "overlay-key");
}

bool setOverlayKey(const std::string &value) {
    return setSettingValue("org.gnome.mutter", "overlay-key", value);
}

struct OverlayKeyGuard {
    std::string originalValue;
    bool modified{false};

    void disable() {
        originalValue = getOverlayKey();
        if (!originalValue.empty() && originalValue != "''") {
            if (setOverlayKey("''")) {
                modified = true;
            }
        }
    }

    void restore() {
        if (modified) {
            setOverlayKey(originalValue.empty() ? "''" : originalValue);
            modified = false;
        }
    }

    ~OverlayKeyGuard() {
        restore();
    }
};

struct AltTabGuard {
    struct Entry {
        std::string schema;
        std::string key;
        std::string originalValue;
        bool changed{false};
    };

    std::vector<Entry> entries{
        {"org.gnome.desktop.wm.keybindings", "switch-applications", "", false},
        {"org.gnome.desktop.wm.keybindings", "switch-applications-backward", "", false}
    };

    void disable() {
        for (auto &entry : entries) {
            entry.originalValue = getSettingValue(entry.schema, entry.key);
            if (setSettingValue(entry.schema, entry.key, "[]")) {
                entry.changed = true;
            }
        }
    }

    void restore() {
        for (auto it = entries.rbegin(); it != entries.rend(); ++it) {
            if (it->changed && !it->originalValue.empty()) {
                setSettingValue(it->schema, it->key, it->originalValue);
                it->changed = false;
            }
            it->originalValue.clear();
        }
    }

    ~AltTabGuard() {
        restore();
    }
};

struct OverviewGuard {
    struct Entry {
        std::string schema;
        std::string key;
        std::string originalValue;
        bool changed{false};
    };

    std::vector<Entry> entries{
        {"org.gnome.shell.keybindings", "toggle-overview", "", false},
        {"org.gnome.shell.keybindings", "shift-overview-up", "", false},
        {"org.gnome.shell.keybindings", "shift-overview-down", "", false}
    };

    void disable() {
        for (auto &entry : entries) {
            entry.originalValue = getSettingValue(entry.schema, entry.key);
            if (setSettingValue(entry.schema, entry.key, "[]")) {
                entry.changed = true;
            }
        }
    }

    void restore() {
        for (auto it = entries.rbegin(); it != entries.rend(); ++it) {
            if (it->changed) {
                std::string value = it->originalValue.empty() ? "[]" : it->originalValue;
                setSettingValue(it->schema, it->key, value);
                it->changed = false;
            }
            it->originalValue.clear();
        }
    }

    ~OverviewGuard() {
        restore();
    }
};

class VTSwitchGuard {
public:
    bool lock() {
#ifdef VT_LOCKSWITCH
        const char *paths[] = {"/dev/tty0", "/dev/console", "/dev/tty"};
        for (const char *path : paths) {
            if (!path) {
                continue;
            }
            fd = open(path, O_RDWR | O_CLOEXEC);
            if (fd >= 0) {
                break;
            }
        }
        if (fd < 0) {
            return false;
        }
        if (ioctl(fd, VT_LOCKSWITCH, 1) == 0) {
            locked = true;
            return true;
        }
        close(fd);
        fd = -1;
#endif
        return false;
    }

    void unlock() {
#ifdef VT_LOCKSWITCH
        if (fd >= 0) {
            if (locked) {
                ioctl(fd, VT_LOCKSWITCH, 0);
                locked = false;
            }
            close(fd);
            fd = -1;
        }
#endif
    }

    ~VTSwitchGuard() {
        unlock();
    }

private:
    int fd{-1};
    bool locked{false};
};


struct X11ErrorTracker {
    bool triggered{false};
    XErrorEvent event{};
    char message[256]{};
};

X11ErrorTracker g_errorTracker;

int x11ErrorHandler(Display *dpy, XErrorEvent *error) {
    g_errorTracker.triggered = true;
    g_errorTracker.event = *error;
    XGetErrorText(dpy, error->error_code, g_errorTracker.message, sizeof(g_errorTracker.message));
    return 0;
}

void resetX11ErrorTracker() {
    g_errorTracker.triggered = false;
    std::memset(&g_errorTracker.event, 0, sizeof(g_errorTracker.event));
    g_errorTracker.message[0] = '\0';
}

struct PamData {
    const std::string *password;
};

passwd *resolvePamUser() {
    uid_t uid = getuid();
    passwd *pw = getpwuid(uid);
    if (pw || uid != 0) {
        return pw;
    }

    auto parseUid = [](const char *value) -> std::optional<uid_t> {
        if (!value || !*value) {
            return std::nullopt;
        }
        errno = 0;
        char *end = nullptr;
        unsigned long parsed = std::strtoul(value, &end, 10);
        if (errno != 0 || !end || *end != '\0') {
            return std::nullopt;
        }
        return static_cast<uid_t>(parsed);
    };

    const char *sudoUidEnv = std::getenv("SUDO_UID");
    if (auto sudoUid = parseUid(sudoUidEnv)) {
        pw = getpwuid(*sudoUid);
        if (pw) {
            return pw;
        }
    }

    const char *sudoUser = std::getenv("SUDO_USER");
    if (sudoUser && *sudoUser) {
        pw = getpwnam(sudoUser);
    }
    return pw;
}

int pamConversation(int num_msg, const pam_message **msg, pam_response **resp, void *appdata_ptr) {
    if (!resp || !msg) {
        return PAM_CONV_ERR;
    }
    if (num_msg <= 0) {
        return PAM_CONV_ERR;
    }

    size_t responseCount = static_cast<size_t>(num_msg);
    pam_response *responses = static_cast<pam_response *>(calloc(responseCount, sizeof(pam_response)));
    if (!responses) {
        return PAM_BUF_ERR;
    }

    PamData *data = static_cast<PamData *>(appdata_ptr);
    for (int i = 0; i < num_msg; ++i) {
        switch (msg[i]->msg_style) {
            case PAM_PROMPT_ECHO_OFF:
            case PAM_PROMPT_ECHO_ON:
                responses[i].resp = strdup(data && data->password ? data->password->c_str() : "");
                break;
            case PAM_ERROR_MSG:
            case PAM_TEXT_INFO:
                responses[i].resp = nullptr;
                break;
            default:
                free(responses);
                return PAM_CONV_ERR;
        }
    }

    *resp = responses;
    return PAM_SUCCESS;
}

bool authenticate(const std::string &password) {
    struct passwd *pw = resolvePamUser();
    if (!pw) {
        return false;
    }

    pam_handle_t *pamh = nullptr;
    PamData data{&password};
    pam_conv conv{pamConversation, &data};

    int ret = pam_start("login", pw->pw_name, &conv, &pamh);
    if (ret != PAM_SUCCESS) {
        return false;
    }

    ret = pam_authenticate(pamh, 0);
    if (ret == PAM_SUCCESS) {
        ret = pam_acct_mgmt(pamh, 0);
    }

    pam_end(pamh, ret);
    return ret == PAM_SUCCESS;
}

Cursor makeInvisibleCursor(Display *dpy, Window root) {
    static char data[] = {0};
    Pixmap blank = XCreateBitmapFromData(dpy, root, data, 1, 1);
    XColor dummy;
    memset(&dummy, 0, sizeof(dummy));
    Cursor cursor = XCreatePixmapCursor(dpy, blank, blank, &dummy, &dummy, 0, 0);
    XFreePixmap(dpy, blank);
    return cursor;
}
}

int main(int argc, char **argv) {
    if (!ensureSleepInhibition(argc, argv)) {
        std::cerr << "vibelock: warning: automatic suspend is not inhibited" << std::endl;
    }
    std::cerr << "vibelock: started" << std::endl;
    Display *dpy = XOpenDisplay(nullptr);
    if (!dpy) {
        std::cerr << "vibelock: cannot open display" << std::endl;
        return 1;
    }

    bool wantEvdevGrab = true;
    if (const char *env = std::getenv(kEvdevEnvVar)) {
        wantEvdevGrab = std::strcmp(env, "0") != 0;
    }
    EvdevGrabber evdevGrabber;
    bool evdevActive = false;
    if (wantEvdevGrab) {
        if (evdevGrabber.initialize()) {
            evdevActive = true;
            std::cerr << "vibelock: evdev grab enabled" << std::endl;
        } else {
            std::cerr << "vibelock: evdev grab requested but initialization failed" << std::endl;
        }
    }

    OverlayKeyGuard overlayGuard;
    overlayGuard.disable();

    AltTabGuard altTabGuard;
    altTabGuard.disable();

    OverviewGuard overviewGuard;
    overviewGuard.disable();

    VTSwitchGuard vtGuard;
    if (vtGuard.lock()) {
        std::cerr << "vibelock: VT switching locked" << std::endl;
    } else {
        std::cerr << "vibelock: warning: unable to lock VT switching" << std::endl;
    }

    int screen = DefaultScreen(dpy);
    Window root = RootWindow(dpy, screen);
    const unsigned int width = static_cast<unsigned int>(std::max(0, DisplayWidth(dpy, screen)));
    const unsigned int height = static_cast<unsigned int>(std::max(0, DisplayHeight(dpy, screen)));
    const unsigned int depth = static_cast<unsigned int>(std::max(0, DefaultDepth(dpy, screen)));

    Colormap colormap = DefaultColormap(dpy, screen);
    const unsigned long backgroundPixel = BlackPixel(dpy, screen);
    unsigned long textPixel = WhitePixel(dpy, screen);
    XColor greenText{};
    greenText.red = 0;
    greenText.green = 65535;
    greenText.blue = 0;
    greenText.flags = DoRed | DoGreen | DoBlue;
    if (XAllocColor(dpy, colormap, &greenText)) {
        textPixel = greenText.pixel;
    } else {
        std::cerr << "vibelock: warning: unable to allocate green text color, using default" << std::endl;
    }

    struct MonitorRect {
        int x{0};
        int y{0};
        int width{0};
        int height{0};
    };

    auto queryMonitors = [&]() -> std::vector<MonitorRect> {
        std::vector<MonitorRect> monitors;
        int count = 0;
        if (XineramaIsActive(dpy)) {
            XineramaScreenInfo *screens = XineramaQueryScreens(dpy, &count);
            if (screens) {
                for (int i = 0; i < count; ++i) {
                    monitors.push_back(
                        {screens[i].x_org, screens[i].y_org, screens[i].width, screens[i].height});
                }
                XFree(screens);
            }
        }
        if (monitors.empty()) {
            monitors.push_back({0, 0, static_cast<int>(width), static_cast<int>(height)});
        }
        return monitors;
    };

    const std::vector<MonitorRect> monitors = queryMonitors();

    XSetWindowAttributes attrs{};
    attrs.override_redirect = True;
    attrs.background_pixel = backgroundPixel;
    attrs.event_mask = KeyPressMask | KeyReleaseMask | ExposureMask;

    Window win = XCreateWindow(
        dpy,
        root,
        0,
        0,
        width,
        height,
        0,
        CopyFromParent,
        InputOutput,
        CopyFromParent,
        CWOverrideRedirect | CWBackPixel | CWEventMask,
        &attrs);

    if (!win) {
        std::cerr << "vibelock: failed to create window" << std::endl;
        XCloseDisplay(dpy);
        return 1;
    }

    Cursor invisible = makeInvisibleCursor(dpy, root);
    XDefineCursor(dpy, win, invisible);

    // Separate invisible InputOnly window to own the keyboard focus (many compositors refuse focus to override-redirect windows).
    auto waitUntilViewable = [&](Window w) {
        if (!w) {
            return false;
        }
        for (int i = 0; i < 50; ++i) {
            XWindowAttributes attr;
            if (XGetWindowAttributes(dpy, w, &attr) && attr.map_state == IsViewable) {
                return true;
            }
            XSync(dpy, False);
            usleep(10000);
        }
        return false;
    };

    XSetWindowAttributes focusAttrs{};
    focusAttrs.override_redirect = False;
    focusAttrs.event_mask = KeyPressMask | KeyReleaseMask | FocusChangeMask | StructureNotifyMask;
    focusAttrs.background_pixel = backgroundPixel;
    focusAttrs.border_pixel = backgroundPixel;
    Window focusWin = XCreateWindow(
        dpy,
        root,
        0,
        0,
        1,
        1,
        0,
        CopyFromParent,
        InputOutput,
        CopyFromParent,
        CWEventMask | CWBackPixel | CWBorderPixel | CWOverrideRedirect,
        &focusAttrs);
    if (focusWin) {
        XMapRaised(dpy, focusWin);
        if (!waitUntilViewable(focusWin)) {
        }
        XSelectInput(dpy, focusWin, KeyPressMask | KeyReleaseMask | FocusChangeMask);
    }

    Pixmap backBuffer = XCreatePixmap(dpy, win, width, height, depth);
    Drawable gcDrawable = backBuffer ? static_cast<Drawable>(backBuffer) : static_cast<Drawable>(win);
    GC gc = XCreateGC(dpy, gcDrawable, 0, nullptr);
    XSetForeground(dpy, gc, textPixel);

    constexpr int kScaleFactor = 10;
    const std::string defaultMessage = "Screen locked";
    const std::string blockingMessage = kBlockingMessage;
    std::string messageText = defaultMessage;
    const int baseSpacing = 4;

    XFontStruct *fontInfo = XQueryFont(dpy, XGContextFromGC(gc));

    struct ScaledText {
        XImage *image{nullptr};
        int width{0};
        int height{0};
    };

    auto destroyScaledText = [&](ScaledText &text) {
        if (text.image) {
            XDestroyImage(text.image);
            text.image = nullptr;
            text.width = 0;
            text.height = 0;
        }
    };

    auto measureText = [&](const char *text, int len, int &widthOut, int &heightOut) {
        if (fontInfo) {
            int direction = 0;
            int ascent = 0;
            int descent = 0;
            XCharStruct overall{};
            XTextExtents(fontInfo, text, len, &direction, &ascent, &descent, &overall);
            widthOut = overall.width;
            heightOut = ascent + descent;
        } else {
            widthOut = len * 8;
            heightOut = 10;
        }

        if (widthOut <= 0) {
            widthOut = len * 8;
        }
        if (heightOut <= 0) {
            heightOut = 10;
        }
    };

    auto textHeight = [&](const char *text) -> int {
        if (!text) {
            return 0;
        }
        int len = static_cast<int>(std::strlen(text));
        if (len == 0) {
            return 0;
        }
        int widthOut = 0;
        int heightOut = 0;
        measureText(text, len, widthOut, heightOut);
        return heightOut;
    };

    auto clampUnsigned = [](int value) -> unsigned int {
        return value <= 0 ? 0U : static_cast<unsigned int>(value);
    };

    auto buildScaledImage = [&](const char *text) -> ScaledText {
        ScaledText result;
        if (!text) {
            return result;
        }

        int len = static_cast<int>(std::strlen(text));
        if (len == 0) {
            return result;
        }

        int textWidth = 0;
        int textHeightVal = 0;
        measureText(text, len, textWidth, textHeightVal);

        int scaledWidth = textWidth * kScaleFactor;
        int scaledHeight = textHeightVal * kScaleFactor;

        const unsigned int pixWidth = clampUnsigned(textWidth);
        const unsigned int pixHeight = clampUnsigned(textHeightVal);
        Pixmap textPixmap = XCreatePixmap(dpy, win, pixWidth, pixHeight, depth);
        if (!textPixmap) {
            return result;
        }

        GC textGC = XCreateGC(dpy, textPixmap, 0, nullptr);
        if (!textGC) {
            XFreePixmap(dpy, textPixmap);
            return result;
        }

        XSetForeground(dpy, textGC, backgroundPixel);
        XFillRectangle(dpy, textPixmap, textGC, 0, 0, pixWidth, pixHeight);
        XSetForeground(dpy, textGC, textPixel);
        int baseline = fontInfo ? fontInfo->ascent : textHeightVal - baseSpacing;
        if (baseline < 0) {
            baseline = textHeightVal;
        }
        XDrawString(dpy, textPixmap, textGC, 0, baseline, text, len);
        XFreeGC(dpy, textGC);

        XImage *src = XGetImage(dpy, textPixmap, 0, 0, pixWidth, pixHeight, AllPlanes, ZPixmap);
        XFreePixmap(dpy, textPixmap);
        if (!src) {
            return result;
        }

        const unsigned int imageDepth = static_cast<unsigned int>(std::max(0, DefaultDepth(dpy, screen)));
        XImage *dst = XCreateImage(dpy, DefaultVisual(dpy, screen), imageDepth, ZPixmap,
                                   0, nullptr, clampUnsigned(scaledWidth), clampUnsigned(scaledHeight), 32, 0);
        if (!dst) {
            XDestroyImage(src);
            return result;
        }

        size_t dataSize = static_cast<size_t>(dst->bytes_per_line) * static_cast<size_t>(dst->height);
        dst->data = static_cast<char *>(malloc(dataSize));
        if (!dst->data) {
            XDestroyImage(dst);
            XDestroyImage(src);
            return result;
        }
        std::memset(dst->data, 0, dataSize);

        for (int y = 0; y < scaledHeight; ++y) {
            for (int x = 0; x < scaledWidth; ++x) {
                unsigned long pixel = XGetPixel(src, x / kScaleFactor, y / kScaleFactor);
                XPutPixel(dst, x, y, pixel);
            }
        }

        XDestroyImage(src);
        result.image = dst;
        result.width = scaledWidth;
        result.height = scaledHeight;
        return result;
    };

    auto targetDrawable = [&]() -> Drawable {
        return backBuffer ? static_cast<Drawable>(backBuffer) : static_cast<Drawable>(win);
    };

    auto clearTarget = [&]() {
        Drawable target = targetDrawable();
        XSetForeground(dpy, gc, backgroundPixel);
        XFillRectangle(dpy, target, gc, 0, 0, width, height);
        XSetForeground(dpy, gc, textPixel);
    };

    auto drawFallback = [&](const MonitorRect &mon, const char *text, int y, int &heightOut) {
        heightOut = 0;
        if (!text) {
            return;
        }
        int len = static_cast<int>(std::strlen(text));
        if (len == 0) {
            return;
        }
        int textWidth = 0;
        int textHeightVal = 0;
        measureText(text, len, textWidth, textHeightVal);
        int x = mon.x + std::max(0, (mon.width - textWidth) / 2);
        int baseline = mon.y + y + (fontInfo ? fontInfo->ascent : textHeightVal);
        XDrawString(dpy, targetDrawable(), gc, x, baseline, text, len);
        heightOut = textHeightVal;
    };

    ScaledText messageImage = buildScaledImage(messageText.c_str());
    ScaledText passwordImage;
    std::string passwordFallbackText;
    std::string buffer;
    bool needsRedraw = true;

    auto setMessageText = [&](const std::string &text) {
        if (messageText == text) {
            return;
        }
        messageText = text;
        destroyScaledText(messageImage);
        messageImage = buildScaledImage(messageText.c_str());
        needsRedraw = true;
    };

    auto drawContent = [&]() {
        Drawable target = targetDrawable();
        auto drawImage = [&](const MonitorRect &mon, const ScaledText &img, int y) {
            if (!img.image) {
                return;
            }
            int x = mon.x + std::max(0, (mon.width - img.width) / 2);
            XPutImage(dpy,
                      target,
                      gc,
                      img.image,
                      0,
                      0,
                      x,
                      mon.y + y,
                      clampUnsigned(img.width),
                      clampUnsigned(img.height));
        };

        bool hasPassword = passwordImage.image || !passwordFallbackText.empty();
        int spacing = hasPassword ? baseSpacing * kScaleFactor : 0;

        for (const auto &mon : monitors) {
            int totalHeight = messageImage.image ? messageImage.height : textHeight(messageText.c_str());
            if (hasPassword) {
                int pwdHeight = passwordImage.image ? passwordImage.height : textHeight(passwordFallbackText.c_str());
                totalHeight += spacing + pwdHeight;
            }

            int currentY = std::max(0, (mon.height - totalHeight) / 2);
            if (messageImage.image) {
                drawImage(mon, messageImage, currentY);
                currentY += messageImage.height;
            } else {
                int drawn = 0;
                drawFallback(mon, messageText.c_str(), currentY, drawn);
                currentY += drawn;
            }

            if (hasPassword) {
                currentY += spacing;
                if (passwordImage.image) {
                    drawImage(mon, passwordImage, currentY);
                } else {
                    int drawn = 0;
                    drawFallback(mon, passwordFallbackText.c_str(), currentY, drawn);
                    currentY += drawn;
                }
            }
        }
    };

    auto redraw = [&]() {
        clearTarget();
        drawContent();
        if (backBuffer) {
            XCopyArea(dpy, backBuffer, win, gc, 0, 0, width, height, 0, 0);
        }
        XFlush(dpy);
    };

    auto forceRedraw = [&]() {
        redraw();
        needsRedraw = false;
    };

    auto flushInputQueues = [&]() {
        while (XPending(dpy) > 0) {
            XEvent drop;
            XNextEvent(dpy, &drop);
        }
        if (evdevActive) {
            RawKeyEvent raw;
            while (evdevGrabber.popEvent(raw, 0)) {
            }
        }
    };

    auto updatePasswordVisual = [&]() {
        destroyScaledText(passwordImage);
        passwordFallbackText.clear();
        if (!buffer.empty()) {
            passwordFallbackText.assign(buffer.size(), '*');
            passwordImage = buildScaledImage(passwordFallbackText.c_str());
        }
        needsRedraw = true;
    };

    auto flushPasswordBuffer = [&]() {
        buffer.clear();
        updatePasswordVisual();
    };

    enum class SubmitResult {
        NoInput,
        Authenticated,
        Rejected,
    };

    auto submitBuffer = [&]() -> SubmitResult {
        if (buffer.empty()) {
            flushPasswordBuffer();
            return SubmitResult::NoInput;
        }
        bool ok = authenticate(buffer);
        flushPasswordBuffer();
        return ok ? SubmitResult::Authenticated : SubmitResult::Rejected;
    };

    auto applyBlockingPenalty = [&]() {
        flushPasswordBuffer();
        flushInputQueues();
        const int totalSeconds = static_cast<int>(kBlockingDuration.count());
        for (int remaining = totalSeconds; remaining > 0; --remaining) {
            std::string countdownText = blockingMessage + std::string(" ") + std::to_string(remaining);
            setMessageText(countdownText);
            forceRedraw();
            std::this_thread::sleep_for(std::chrono::seconds(1));
            flushInputQueues();
        }
        flushPasswordBuffer();
        setMessageText(defaultMessage);
        forceRedraw();
    };

    int (*previousErrorHandler)(Display *, XErrorEvent *) = XSetErrorHandler(x11ErrorHandler);

    XMapRaised(dpy, win);
    XSync(dpy, False);
    resetX11ErrorTracker();
    Window focusTarget = focusWin ? focusWin : win;
    XSetInputFocus(dpy, focusTarget, RevertToNone, CurrentTime);
    XSync(dpy, False);
    redraw();
    needsRedraw = false;

    auto grabPointer = [&]() -> bool {
        for (int i = 0; i < 50; ++i) {
            if (XGrabPointer(dpy, root, False, ButtonPressMask | ButtonReleaseMask | PointerMotionMask,
                             GrabModeAsync, GrabModeAsync, win, invisible, CurrentTime) == GrabSuccess) {
                return true;
            }
            usleep(10000);
        }
        return false;
    };

    auto grabKeyboard = [&](Window target) -> bool {
        for (int i = 0; i < 50; ++i) {
            if (XGrabKeyboard(dpy, target, False, GrabModeAsync, GrabModeAsync, CurrentTime) == GrabSuccess) {
                return true;
            }
            usleep(10000);
        }
        return false;
    };

    const bool pointerGrabbed = grabPointer();
    bool keyboardGrabbed = grabKeyboard(focusTarget);
    if (!keyboardGrabbed) {
        // As a fallback, try grabbing on the root window (less reliable).
        keyboardGrabbed = grabKeyboard(root);
    }

    if (!pointerGrabbed || !keyboardGrabbed) {
        std::cerr << "vibelock: unable to capture all input, aborting lock" << std::endl;
        if (pointerGrabbed) {
            XUngrabPointer(dpy, CurrentTime);
        }
        if (keyboardGrabbed) {
            XUngrabKeyboard(dpy, CurrentTime);
        }
        destroyScaledText(messageImage);
        destroyScaledText(passwordImage);
        if (fontInfo) {
            XFreeFontInfo(nullptr, fontInfo, 1);
        }
        XFreeGC(dpy, gc);
        XDestroyWindow(dpy, win);
        XFreeCursor(dpy, invisible);
        XCloseDisplay(dpy);
        return 1;
    }

    auto queryMasterKeyboard = [&]() -> int {
        int nDevices = 0;
        XIDeviceInfo *info = XIQueryDevice(dpy, XIAllMasterDevices, &nDevices);
        int result = -1;
        for (int i = 0; i < nDevices; ++i) {
            if (info[i].use == XIMasterKeyboard) {
                result = info[i].deviceid;
                break;
            }
        }
        if (info) {
            XIFreeDeviceInfo(info);
        }
        return result;
    };

    auto grabXiKeyboard = [&](int deviceId) -> bool {
        if (deviceId < 0) {
            return false;
        }
        XIEventMask mask;
        unsigned char maskData[XIMaskLen(XI_RawKeyRelease)] = {0};
        XISetMask(maskData, XI_RawKeyPress);
        XISetMask(maskData, XI_RawKeyRelease);
        mask.deviceid = deviceId;
        mask.mask_len = sizeof(maskData);
        mask.mask = maskData;
        int status = XIGrabDevice(dpy, deviceId, focusTarget, CurrentTime, None, XIGrabModeAsync, XIGrabModeAsync,
                                  False, &mask);
        return status == Success;
    };

    auto ungrabXiKeyboard = [&](int deviceId) {
        if (deviceId >= 0) {
            XIUngrabDevice(dpy, deviceId, CurrentTime);
        }
    };

    constexpr size_t kXiPointerMaskLength = XIMaskLen(XI_GestureSwipeEnd);
    auto fillPointerMask = [&](std::array<unsigned char, kXiPointerMaskLength> &maskData) {
        maskData.fill(0);
        XISetMask(maskData.data(), XI_ButtonPress);
        XISetMask(maskData.data(), XI_ButtonRelease);
        XISetMask(maskData.data(), XI_Motion);
        XISetMask(maskData.data(), XI_TouchBegin);
        XISetMask(maskData.data(), XI_TouchUpdate);
        XISetMask(maskData.data(), XI_TouchEnd);
        XISetMask(maskData.data(), XI_TouchOwnership);
        XISetMask(maskData.data(), XI_RawButtonPress);
        XISetMask(maskData.data(), XI_RawButtonRelease);
        XISetMask(maskData.data(), XI_RawMotion);
        XISetMask(maskData.data(), XI_RawTouchBegin);
        XISetMask(maskData.data(), XI_RawTouchUpdate);
        XISetMask(maskData.data(), XI_RawTouchEnd);
        XISetMask(maskData.data(), XI_GesturePinchBegin);
        XISetMask(maskData.data(), XI_GesturePinchUpdate);
        XISetMask(maskData.data(), XI_GesturePinchEnd);
        XISetMask(maskData.data(), XI_GestureSwipeBegin);
        XISetMask(maskData.data(), XI_GestureSwipeUpdate);
        XISetMask(maskData.data(), XI_GestureSwipeEnd);
    };

    auto grabXiPointerDevice = [&](int deviceId) -> bool {
        if (deviceId < 0) {
            return false;
        }
        XIEventMask mask;
        std::array<unsigned char, kXiPointerMaskLength> maskData{};
        fillPointerMask(maskData);
        mask.deviceid = deviceId;
        mask.mask_len = static_cast<int>(maskData.size());
        mask.mask = maskData.data();

        int status = XIGrabDevice(dpy,
                                  deviceId,
                                  win,
                                  CurrentTime,
                                  invisible,
                                  XIGrabModeAsync,
                                  XIGrabModeAsync,
                                  False,
                                  &mask);
        return status == Success;
    };

    auto grabAllXiPointers = [&]() -> std::vector<int> {
        std::vector<int> grabbed;
        int nDevices = 0;
        XIDeviceInfo *info = XIQueryDevice(dpy, XIAllDevices, &nDevices);
        if (!info) {
            return grabbed;
        }
        for (int i = 0; i < nDevices; ++i) {
            if (info[i].use != XIMasterPointer && info[i].use != XISlavePointer) {
                continue;
            }
            if (grabXiPointerDevice(info[i].deviceid)) {
                grabbed.push_back(info[i].deviceid);
            }
        }
        XIFreeDeviceInfo(info);
        return grabbed;
    };

    auto ungrabXiPointerDevices = [&](const std::vector<int> &devices) {
        for (int deviceId : devices) {
            if (deviceId >= 0) {
                XIUngrabDevice(dpy, deviceId, CurrentTime);
            }
        }
    };

    int masterKeyboardId = queryMasterKeyboard();
    bool xiKeyboardGrabbed = grabXiKeyboard(masterKeyboardId);
    std::vector<int> xiPointerDevices = grabAllXiPointers();
    bool xiPointerGrabbed = !xiPointerDevices.empty();

    bool running = true;
    auto handleSubmitResult = [&](SubmitResult result) {
        if (result == SubmitResult::Authenticated) {
            running = false;
        } else if (result == SubmitResult::Rejected) {
            applyBlockingPenalty();
        }
    };
    auto isSuperKey = [](KeySym sym) {
        return sym == XK_Super_L || sym == XK_Super_R;
    };
    auto logSuperKey = [&](const char *phase) {
        std::cerr << "vibelock: Super key " << phase << std::endl;
    };

    auto handleKeyPress = [&](KeySym sym, const char *input, int len) {
        if (isSuperKey(sym)) {
            logSuperKey("pressed");
            return;
        }

        bool bufferChanged = false;
        bool handled = false;

        if (len > 0) {
            for (int i = 0; i < len; ++i) {
                unsigned char c = static_cast<unsigned char>(input[i]);
                if (c == '\r' || c == '\n') {
                    SubmitResult result = submitBuffer();
                    handleSubmitResult(result);
                    handled = true;
                    break;
                } else if (c == '\b' || c == 0x7f) {
                    if (!buffer.empty()) {
                        buffer.pop_back();
                        bufferChanged = true;
                    }
                    handled = true;
                } else if (c == 0x1b) {
                    if (!buffer.empty()) {
                        buffer.clear();
                        bufferChanged = true;
                    }
                    handled = true;
                } else {
                    if (buffer.size() >= kMaxPasswordLength) {
                        applyBlockingPenalty();
                        handled = true;
                        break;
                    }
                    buffer.push_back(static_cast<char>(c));
                    bufferChanged = true;
                    handled = true;
                }
            }
        }

        if (!handled && running) {
            if (sym == XK_Return) {
                SubmitResult result = submitBuffer();
                handleSubmitResult(result);
                handled = true;
            } else if (sym == XK_BackSpace) {
                if (!buffer.empty()) {
                    buffer.pop_back();
                    bufferChanged = true;
                }
                handled = true;
            } else if (sym == XK_Escape) {
                if (!buffer.empty()) {
                    buffer.clear();
                    bufferChanged = true;
                }
                handled = true;
            }
        }

        if (bufferChanged) {
            updatePasswordVisual();
        }
    };

    auto handleKeyRelease = [&](KeySym sym) {
        if (isSuperKey(sym)) {
            logSuperKey("released");
        }
    };

    auto handleXEvent = [&](XEvent ev) {
        if (ev.type == Expose) {
            needsRedraw = true;
        } else if (ev.type == KeyPress) {
            KeySym sym;
            char input[32];
            int len = XLookupString(&ev.xkey, input, sizeof(input), &sym, nullptr);
            handleKeyPress(sym, input, len);
        } else if (ev.type == KeyRelease) {
            KeySym sym = XLookupKeysym(&ev.xkey, 0);
            handleKeyRelease(sym);
        }
    };

    const bool useEvdevInput = evdevActive;
    unsigned int evdevState = 0;
    bool evdevCapsLock = false;

    auto setStateBit = [&](unsigned int mask, bool enable) {
        if (enable) {
            evdevState |= mask;
        } else {
            evdevState &= ~mask;
        }
    };

    auto updateModifierState = [&](int code, bool pressed, bool isRepeat) {
        if (isRepeat) {
            return;
        }
        switch (code) {
            case KEY_LEFTSHIFT:
            case KEY_RIGHTSHIFT:
                setStateBit(ShiftMask, pressed);
                break;
            case KEY_LEFTCTRL:
            case KEY_RIGHTCTRL:
                setStateBit(ControlMask, pressed);
                break;
            case KEY_LEFTALT:
            case KEY_RIGHTALT:
                setStateBit(Mod1Mask, pressed);
                break;
            case KEY_LEFTMETA:
            case KEY_RIGHTMETA:
                setStateBit(Mod4Mask, pressed);
                break;
            case KEY_CAPSLOCK:
                if (pressed) {
                    evdevCapsLock = !evdevCapsLock;
                    setStateBit(LockMask, evdevCapsLock);
                }
                break;
            default:
                break;
        }
    };

    auto keycodeToKeysym = [&](unsigned int keycode) -> KeySym {
        if (keycode > 255) {
            return NoSymbol;
        }
        KeyCode keyCodeValue = static_cast<KeyCode>(keycode);
        KeySym sym = XkbKeycodeToKeysym(dpy, keyCodeValue, 0, 0);
        if (sym != NoSymbol) {
            return sym;
        }
        int keysymsPerCode = 0;
        KeySym *mapping = XGetKeyboardMapping(dpy, keyCodeValue, 1, &keysymsPerCode);
        if (mapping) {
            if (keysymsPerCode > 0) {
                sym = mapping[0];
            }
            XFree(mapping);
        }
        return sym;
    };

    auto processEvdevEvent = [&](const RawKeyEvent &raw) {
        if (raw.code < 0) {
            return;
        }
        if (!running) {
            return;
        }
        bool isRepeat = raw.value == 2;
        bool pressed = raw.value == 1 || isRepeat;
        if (!pressed && raw.value != 0) {
            return;
        }

        updateModifierState(raw.code, pressed, isRepeat);

        unsigned int keycode = static_cast<unsigned int>(raw.code) + 8;
        if (keycode > 255) {
            return;
        }

        XKeyEvent fake{};
        fake.display = dpy;
        fake.window = focusTarget;
        fake.root = root;
        fake.subwindow = None;
        fake.time = CurrentTime;
        fake.x = fake.y = fake.x_root = fake.y_root = 0;
        fake.state = evdevState;
        fake.keycode = keycode;
        fake.same_screen = True;
        fake.type = pressed ? KeyPress : KeyRelease;

        KeySym sym = keycodeToKeysym(keycode);
        if (pressed) {
            char input[32];
            int len = XLookupString(&fake, input, sizeof(input), &sym, nullptr);
            handleKeyPress(sym, input, len);
        } else {
            handleKeyRelease(sym);
        }
    };

    while (running) {
        bool processed = false;

        while (XPending(dpy) > 0) {
            XEvent ev;
            XNextEvent(dpy, &ev);
            handleXEvent(ev);
            processed = true;
            if (!running) {
                break;
            }
        }

        if (!running) {
            break;
        }

        if (useEvdevInput) {
            RawKeyEvent raw;
            if (evdevGrabber.popEvent(raw, processed ? 0 : 50)) {
                processEvdevEvent(raw);
                processed = true;
                if (!running) {
                    break;
                }
                // Drain any queued events without waiting.
                while (evdevGrabber.popEvent(raw, 0)) {
                    processEvdevEvent(raw);
                    if (!running) {
                        break;
                    }
                }
            } else if (!processed) {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
        } else if (!processed) {
            XEvent ev;
            XNextEvent(dpy, &ev);
            handleXEvent(ev);
        }

        if (!running) {
            break;
        }

        if (needsRedraw) {
            redraw();
            needsRedraw = false;
        }
    }

    if (evdevActive) {
        evdevGrabber.shutdown();
    }

    XUngrabKeyboard(dpy, CurrentTime);
    XUngrabPointer(dpy, CurrentTime);

    destroyScaledText(messageImage);
    destroyScaledText(passwordImage);
    if (fontInfo) {
        XFreeFontInfo(nullptr, fontInfo, 1);
    }
    if (focusWin) {
        XDestroyWindow(dpy, focusWin);
    }
    if (xiKeyboardGrabbed) {
        ungrabXiKeyboard(masterKeyboardId);
    }
    if (xiPointerGrabbed) {
        ungrabXiPointerDevices(xiPointerDevices);
    }
    XSetErrorHandler(previousErrorHandler);
    if (backBuffer) {
        XFreePixmap(dpy, backBuffer);
    }
    XFreeGC(dpy, gc);
    XDestroyWindow(dpy, win);
    XFreeCursor(dpy, invisible);
    XCloseDisplay(dpy);
    std::cerr << "vibelock: stopped" << std::endl;
    return 0;
}
