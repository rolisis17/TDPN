#pragma once
#include <linux/netlink.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <linux/rtnetlink.h>
#include <unistd.h>
#include <iostream>
#include <net/if.h>
#include <cstring>
#include <stdexcept>
#include <netinet/in.h>
#include <arpa/inet.h>

int StartInterface(void);
static void addAttr(nlmsghdr* nlh, size_t maxlen, int type, const void* data, size_t data_len);