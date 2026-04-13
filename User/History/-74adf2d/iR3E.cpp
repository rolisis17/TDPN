#include "Vpn.hpp"

int StartInterface(void) {
    std::string answer;
    
    printf("Select:\n0 - connect to TPN\n1 - Become TPN\n");
    std::getline(std::cin, answer);
    
    printf(answer.c_str(), answer.length());
    return 0;
}


int main(int ac, char** av){
    int sock = getSocket();
    int if_index = if_nametoindex("tun0");
    set_link_up(sock, if_index);

    if (sock != 0)
        return -1;

    return 0;
}

int getSocket(void) {
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    sockaddr_nl addr{};
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = 0;

    if (bind(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }

    return sock;
}

void set_link_up(int sock, int if_index)
{
    struct {
        nlmsghdr nlh;
        ifinfomsg ifi;
    } req{};

    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(ifinfomsg));
    req.nlh.nlmsg_type = RTM_NEWLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

    req.ifi.ifi_family = AF_UNSPEC;
    req.ifi.ifi_index = if_index;
    req.ifi.ifi_change = IFF_UP;
    req.ifi.ifi_flags = IFF_UP;

    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;

    sendto(sock, &req, req.nlh.nlmsg_len, 0,
           (sockaddr*)&kernel, sizeof(kernel));
}
