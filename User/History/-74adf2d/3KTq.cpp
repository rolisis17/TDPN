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