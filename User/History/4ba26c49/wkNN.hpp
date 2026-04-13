#include "NetlinkSocket.hpp"
#include "../Vpn.hpp"

void addIPAddress(NetlinkSocket& sock, int ifIndex, const std::string& ip, int prefix);