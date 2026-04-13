#pragma once

#include "NetlinkSocket.hpp"
#include <string>
#include "Vp"

class RouteManager {
public:
    explicit RouteManager(NetlinkSocket& sock);

    void bringInterfaceUp(const std::string& ifName);

    void addIPAddress(const std::string& ifName,
                      const std::string& ip,
                      int prefix);

    void addDefaultRoute(const std::string& ifName,
                         const std::string& gateway);

private:
    NetlinkSocket& sock_;
};
