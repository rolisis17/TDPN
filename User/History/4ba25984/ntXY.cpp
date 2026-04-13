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

void RouteManager::bringInterfaceUp(const std::string& ifName)
{
    int ifIndex = if_nametoindex(ifName.c_str());
    if (!ifIndex)
        throw std::runtime_error("Interface not found");

    char buffer[4096]{};

    nlmsghdr* nlh = (nlmsghdr*)buffer;
    ifinfomsg* ifi = (ifinfomsg*)NLMSG_DATA(nlh);

    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(ifinfomsg));
    nlh->nlmsg_type = RTM_NEWLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_index = ifIndex;
    ifi->ifi_change = IFF_UP;
    ifi->ifi_flags = IFF_UP;

    sock_.send(nlh, nlh->nlmsg_len);
    sock_.receive();
}

void RouteManager::addIPAddress(const std::string& ifName, const std::string& ip, int prefix)
{
    int ifIndex = if_nametoindex(ifName.c_str());
    if (!ifIndex)
        throw std::runtime_error("Interface not found");

    char buffer[4096]{};

    nlmsghdr* nlh = (nlmsghdr*)buffer;
    ifaddrmsg* ifa = (ifaddrmsg*)NLMSG_DATA(nlh);

    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(ifaddrmsg));
    nlh->nlmsg_type = RTM_NEWADDR;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE;

    ifa->ifa_family = AF_INET;
    ifa->ifa_prefixlen = prefix;
    ifa->ifa_index = ifIndex;

    in_addr addr{};
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1)
        throw std::runtime_error("Invalid IP address");

    addAttr(nlh, sizeof(buffer), IFA_LOCAL, &addr, sizeof(addr));
    addAttr(nlh, sizeof(buffer), IFA_ADDRESS, &addr, sizeof(addr));

    sock_.send(nlh, nlh->nlmsg_len);
    sock_.receive();
}

void RouteManager::addDefaultRoute(const std::string& ifName,
                                    const std::string& gateway)
{
    int ifIndex = if_nametoindex(ifName.c_str());
    if (!ifIndex)
        throw std::runtime_error("Interface not found");

    char buffer[4096]{};

    nlmsghdr* nlh = (nlmsghdr*)buffer;
    rtmsg* rtm = (rtmsg*)NLMSG_DATA(nlh);

    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
    nlh->nlmsg_type = RTM_NEWROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE;

    rtm->rtm_family = AF_INET;
    rtm->rtm_table = RT_TABLE_MAIN;
    rtm->rtm_protocol = RTPROT_BOOT;
    rtm->rtm_scope = RT_SCOPE_UNIVERSE;
    rtm->rtm_type = RTN_UNICAST;
    rtm->rtm_dst_len = 0; // default route

    in_addr gw{};
    if (inet_pton(AF_INET, gateway.c_str(), &gw) != 1)
        throw std::runtime_error("Invalid gateway");

    addAttr(nlh, sizeof(buffer), RTA_GATEWAY, &gw, sizeof(gw));
    addAttr(nlh, sizeof(buffer), RTA_OIF, &ifIndex, sizeof(ifIndex));

    sock_.send(nlh, nlh->nlmsg_len);
    sock_.receive();
}
