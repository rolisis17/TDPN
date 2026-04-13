#pragma once
#include <linux/netlink.h>
#include <sys/socket.h>
#include <unistd.h>

class NetlinkSocket {
public:
    NetlinkSocket();
    ~NetlinkSocket();

    void send(void* msg, size_t len);
    void receive();

private:
    int sock_;
};
