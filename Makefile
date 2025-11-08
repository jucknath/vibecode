CXX := g++
CXXFLAGS := -std=c++17 -Werror -fstack-protector-strong -fcf-protection=full -fstack-clash-protection \
            -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wcast-qual -Wformat=2 -Wundef \
            -Werror=float-equal -Wshadow -Wcast-align -Wunused -Wnull-dereference -Wdouble-promotion \
            -Wimplicit-fallthrough -Wextra-semi -Woverloaded-virtual -Wnon-virtual-dtor -Wold-style-cast
LDLIBS := -lX11 -lXi -lXext -lpam -pthread

TARGET := vibelock
SRC := vibelock.cpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET) $(LDLIBS)

clean:
	rm -f $(TARGET)
