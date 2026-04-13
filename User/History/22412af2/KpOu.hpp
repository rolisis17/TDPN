#pragma once
#include <string>

class TunDevice {
public:
    TunDevice(const std::string& name);
    ~TunDevice();

    int fd() const;

    int read(char* buffer, size_t size);
    int write(const char* buffer, size_t size);

private:
    int fd_;
};
