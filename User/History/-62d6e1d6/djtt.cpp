#include "TunDevice.hpp"

void TunnelEngine::run()
{
    char buffer[2000];

    while (true)
    {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(tun_.fd(), &fds);
        FD_SET(udp_.fd(), &fds);

        int maxfd = std::max(tun_.fd(), udp_.fd()) + 1;

        select(maxfd, &fds, nullptr, nullptr, nullptr);

        if (FD_ISSET(tun_.fd(), &fds)) {
            int len = tun_.read(buffer, sizeof(buffer));
            udp_.send(buffer, len);
        }

        if (FD_ISSET(udp_.fd(), &fds)) {
            int len = udp_.receive(buffer, sizeof(buffer));
            tun_.write(buffer, len);
        }
    }
}
