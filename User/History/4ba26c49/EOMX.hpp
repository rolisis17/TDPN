#include "NetlinkSocket.hpp"
#include "../Vpn.hpp"

#pragma once
#include "NetlinkSocket.hpp"
#include <string>

class RouteManager {
public:
    explicit RouteManager(NetlinkSocket& sock);

    void addIPAddress(const std::string& ifName,
                      const std::string& ip,
                      int prefix);

    void bringInterfaceUp(const std::string& ifName);

    void addDefaultRoute(const std::string& ifName,
                         const std::string& gateway);

private:
    NetlinkSocket& sock_;
};