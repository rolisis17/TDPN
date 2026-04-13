#include "NetlinkSocket.hpp"
#include <cstring>
#include <stdexcept>

NetlinkSocket::NetlinkSocket() {
    sock_ = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock_ < 0)
        throw std::runtime_error("Failed to create netlink socket");

    sockaddr_nl addr{};
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();

    if (bind(sock_, (sockaddr*)&addr, sizeof(addr)) < 0)
        throw std::runtime_error("Failed to bind netlink socket");
}

NetlinkSocket::~NetlinkSocket() {
    close(sock_);
}

int NetlinkSocket::getSocket(void){
    
}

void NetlinkSocket::send(void* msg, size_t len) {
    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;

    sendto(sock_, msg, len, 0,
           (sockaddr*)&kernel, sizeof(kernel));
}

void NetlinkSocket::receive() {
    char buffer[8192];
    recv(sock_, buffer, sizeof(buffer), 0);
}
