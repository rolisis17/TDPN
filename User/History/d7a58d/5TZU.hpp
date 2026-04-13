#pragma once
#include <string>
#include <netinet/in.h>

class UdpTransport {
public:
    UdpTransport(int port); // server constructor

    int fd() const;
    int send(const char* data, size_t size);
    int receive(char* buffer, size_t size);

private:
    int sock_;
    sockaddr_in peer_;
};
