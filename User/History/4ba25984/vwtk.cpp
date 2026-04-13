#include "NetlinkSocket.hpp"
#include "../Vpn.hpp" 

void addIPAddress(NetlinkSocket& sock,
                  int ifIndex,
                  const std::string& ip,
                  int prefix)
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

