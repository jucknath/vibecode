# vibelock

vibelock is a minimal X11 screen locker that strives to remove every obvious path for escaping or leaking keystrokes while the session is locked.  It combines classic X11 grabs with low‑level evdev keyboard grabs, gsettings tweaks, and virtual‑terminal switching locks to keep focus on its full‑screen window until the user successfully authenticates with PAM.

## Features
- **X11 + evdev grabs** – locks both the X server input queue and every `/dev/input/event*` keyboard so new devices cannot inject keystrokes.
- **Password auth via PAM** – uses the `login` service by default so any system account policy applies (2FA, LDAP, etc.).
- **GNOME integration guards** – temporarily disables the Super/overview key and Alt‑Tab bindings via `gsettings` so compositors cannot steal focus.
- **VT switch lock** – uses `VT_LOCKSWITCH` to block Ctrl+Alt+Fn console switching while locked.
- **Simple UI** – centered “Screen locked” message with opaque password indicator and exponential backoff when the max length (32 characters) is exceeded or auth fails repeatedly.

## Requirements
| Type | Requirement |
| ---- | ----------- |
| Build | `g++` with C++17 support, `make` |
| Build/Run | X11 headers/libs (`libX11`, `libXi`, `libXext`) |
| Runtime | Linux with evdev (`/dev/input/event*`) access |
| Runtime | PAM (libpam + configured `login` stack) |
| Optional runtime | GNOME/`gsettings` for overlay key and Alt‑Tab suppression |

> **Note:** GSettings calls fail gracefully on non‑GNOME environments; you simply lose the extra shortcuts guard.

## Building
```sh
make
```
This invokes `g++` with all of the hardening and warning flags defined in `Makefile` and links against the libraries listed above.  Output binary: `./vibelock`.

## Running
vibelock needs permission to read and grab `/dev/input/event*` devices and to interact with PAM.  In practice you should run it via a privileged helper:
```sh
sudo VIBELOCK_EVDEV_GRAB=1 ./vibelock
```
- `VIBELOCK_EVDEV_GRAB` (default `1`): set to `0` to skip the evdev layer and rely solely on X11 grabs.  Useful for debugging when you do not have permission to grab input devices.
- PAM user: when invoked under `sudo`, vibelock authenticates you (the invoking user) rather than root by inspecting `SUDO_USER`/`SUDO_UID`.

When the window appears:
1. Type your system password (characters are masked).  Backspace/Escape clear the buffer.
2. Press Enter to submit; PAM decides whether to unlock.
3. After a rejection the locker enforces a five‑second cooldown, flushing all input.

The process exits with `0` after a successful unlock; non‑zero indicates startup or grab failure.

## GNOME/Desktop Integration
- **Overlay (Super) key:** `OverlayKeyGuard` stores `org.gnome.mutter overlay-key`, sets it to `''`, and restores it on exit.
- **Alt‑Tab bindings:** `AltTabGuard` blanks `org.gnome.desktop.wm.keybindings switch-applications(+backward)`.
- These guards require write access to dconf via `gsettings`; ensure `$DBUS_SESSION_BUS_ADDRESS` is exported when launching vibelock from a TTY.

## Security Notes
- evdev grabs rely on opening `/dev/input/event*`; add your user to the `input` group or run via sudo/pkexec.
- PAM failures, sudden device removal, or inability to grab X11/evdev abort the locker to avoid running in a half‑locked state.  Check stderr logs for `vibelock:` messages.
- Password buffers never exceed 32 bytes and are cleared immediately after an attempt.
- Beware of running inside nested compositors or remote X servers; low‑level grabs may not propagate.

## Troubleshooting
| Symptom | Fix |
| ------- | --- |
| `cannot open display` | Ensure `$DISPLAY` and `$XAUTHORITY` point to the active session before launching under sudo (e.g., `sudo env DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY ./vibelock`). |
| `unable to capture all input` | Another locker/compositor already holds a grab, or you lack permission to grab evdev.  Stop other lockers or run with elevated privileges. |
| GNOME shortcuts remain active | Verify `gsettings` is installed and DBus session bus is accessible; otherwise disable those guards manually. |
| PAM rejects known password | Confirm `/etc/pam.d/login` permits local auth and that vibelock resolves the correct user (especially when using privilege escalation tools other than sudo). |

## Development & Contributions
1. Fork/clone the repository.
2. Make sure your toolchain matches the build requirements above.
3. Run `make` before submitting patches.
4. Include rationale, testing notes, and keep new features behind configuration flags when possible.

Because the project is released into the public domain, contributors agree to dedicate their changes to the public domain as well (see below).  If you must retain copyright, clearly mark your files and ensure they are compatible with permissive redistribution.

## License & Copyleft Notes
- Unless stated otherwise, vibelock is dedicated to the public domain via [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/).  Use it without restriction.
- Bundled scripts/binaries link against third‑party libraries (X11, Xi, Xext, PAM) that are under permissive or weak‑copyleft licenses; consult your distribution for exact terms.
- Do **not** add GPL or other strong copyleft code unless you are willing to place it in the public domain; mixing incompatible licenses would prevent redistribution.
- Include attribution voluntarily if your jurisdiction requires it, but no attribution is legally required.

"THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND"—by contributing or redistributing you accept that there is no support obligation.
