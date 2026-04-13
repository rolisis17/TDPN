#include "Vpn.hpp"

int StartInterface(void) {
    std::string answer;
    
    printf("Select:\n0 - connect to TPN\n1 - Become TPN\n");
    std::getline(std::cin, answer);
    
    printf(answer.c_str(), answer.length());
    return 0;
}


int main(int ac, char** av){
    new NetlinkSocket;
    

    if (sock != 0)
        return -1;

    return 0;
}

static void addAttr(nlmsghdr* nlh, size_t maxlen, int type, const void* data, size_t data_len)
{
    size_t len = RTA_LENGTH(data_len);

    if (NLMSG_ALIGN(nlh->nlmsg_len) + len > maxlen)
        throw std::runtime_error("Attribute overflow");

    rtattr* rta = (rtattr*)((char*)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = len;

    memcpy(RTA_DATA(rta), data, data_len);

    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(len);
}