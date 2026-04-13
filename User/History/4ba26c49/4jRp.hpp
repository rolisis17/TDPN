#include "NetlinkSocket.hpp"
#include "../Vpn.hpp"

void addDefaultRoute(NetlinkSocket& sock, int ifIndex, const std::string& gateway)
void addDefaultRoute(NetlinkSocket& sock, int ifIndex, const std::string& gateway)
void addIPAddress(NetlinkSocket& sock, int ifIndex, const std::string& ip, int prefix);