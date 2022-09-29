#ifndef ___NET_CHECK_TYPES_H___
#define ___NET_CHECK_TYPES_H___

#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <mptcpd/plugin.h>
#include <mptcpd/network_monitor.h>

#define TCPOPT_MPTCP 30

#define PLUGIN_NAME "net_check"
#define CHAIN_IN_NAME "check_in"
#define CHAIN_OUT_NAME "check_out"

#define QUEUE_NUM 10 //dynamic??

typedef void (*flooding_function) (char const *name,
                                   struct mptcpd_interface const *i,
                                   struct sockaddr const *sa,
                                   struct mptcpd_pm *pm);

struct tcpoption {
        uint8_t kind;
        uint8_t length;
};

struct net_mask {
        union {
                struct in_addr ipv4;
                struct in6_addr ipv6;
        };
        uint8_t mask;
};

struct net_queues {
        struct l_queue *ipv4;
        struct l_queue *ipv6;
};

struct get_handle_data {
        uint64_t handle;
        uint32_t index;
        uint16_t key;
};

struct conf {
        struct net_queues allowlist;
        struct net_queues blocklist;
        bool use_stun;
        char *stun_server;
        uint16_t stun_port;
};


#endif
