#include "RouteManager.hpp" 

void addIPAddress(NetlinkSocket& sock, int ifIndex, const std::string& ip, int prefix)
{
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
    inet_pton(AF_INET, ip.c_str(), &addr);

    addAttr(nlh, sizeof(buffer), IFA_LOCAL, &addr, sizeof(addr));
    addAttr(nlh, sizeof(buffer), IFA_ADDRESS, &addr, sizeof(addr));

    sock.send(nlh, nlh->nlmsg_len);
    sock.receive();
}

void addDefaultRoute(NetlinkSocket& sock, int ifIndex, const std::string& gateway)
{
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
    inet_pton(AF_INET, gateway.c_str(), &gw);

    addAttr(nlh, sizeof(buffer), RTA_GATEWAY, &gw, sizeof(gw));
    addAttr(nlh, sizeof(buffer), RTA_OIF, &ifIndex, sizeof(ifIndex));

    sock.send(nlh, nlh->nlmsg_len);
    sock.receive();
}