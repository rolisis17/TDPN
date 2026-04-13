#include "RouteManager.hpp"
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <stdexcept>
#include <cstring>

RouteManager::RouteManager(NetlinkSocket& sock)
    : sock_(sock)
{
}
