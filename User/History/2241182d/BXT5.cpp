#include "TunDevice.hpp"
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <stdexcept>

TunDevice::TunDevice(const std::string& name)
{
    fd_ = open("/dev/net/tun", O_RDWR);
    if (fd_ < 0)
        throw std::runtime_error("Failed to open /dev/net/tun");

    ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ);

    if (ioctl(fd_, TUNSETIFF, &ifr) < 0)
        throw std::runtime_error("Failed to create TUN");
}

TunDevice::~TunDevice()
{
    close(fd_);
}

int TunDevice::fd() const { return fd_; }

int TunDevice::read(char* buffer, size_t size)
{
    return ::read(fd_, buffer, size);
}

int TunDevice::write(const char* buffer, size_t size)
{
    return ::write(fd_, buffer, size);
}
