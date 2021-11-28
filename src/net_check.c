#include <mptcpd/plugin.h>
#include <mptcpd/network_monitor.h>

#include <assert.h>
#include <stdlib.h>
#include <stddef.h>
#include <limits.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/tcp.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

#include <ell/util.h>
#include <ell/log.h>
#include <ell/queue.h>
#include <ell/settings.h>
#include <ell/strv.h>
#include <ell/uintset.h>
#include <ell/hashmap.h>

#include <libmnl/libmnl.h>

#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

#include <libstuncli/libstuncli.h>

#define TCPOPT_MPTCP 30

#define NFT_TABLE_NAME "net_check"
#define NFT_CHAIN_IN_NAME "check_in"
#define NFT_CHAIN_OUT_NAME "check_out"

#define NFT_QUEUE_NUM 10 //dynamic??

typedef void (*flooding_function) (char const *name,
                                   struct mptcpd_interface const *i,
                                   struct sockaddr const *sa,
                                   struct mptcpd_pm *pm);

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

struct conf {
        struct net_queues whitelist;
        struct net_queues blacklist;
        bool use_stun;
        char *stun_server;
        uint16_t stun_port;
};

struct conf config = {
        .whitelist = {
                .ipv4 = NULL,
                .ipv6 = NULL
        },
        .blacklist = { 
                .ipv4 = NULL,
                .ipv6 = NULL
        },
        .use_stun = false,
        .stun_server = NULL,
        .stun_port = 0
};

struct pair {
        uint64_t handle_in;
        uint64_t handle_out;
};

static struct l_uintset *whitelisted_ifs;
static struct l_uintset *blacklisted_ifs;

static char const name[] = "net_check"; //maybe macro

static struct mnl_socket *so;
static uint16_t portid;

static struct l_uintset *handles;
static struct l_hashmap *ifs_handle;

// ----------------------------------------------------------------------


static void add_expr_meta(struct nftnl_rule *rule,
                          uint8_t reg,
                          uint8_t key)
{
        struct nftnl_expr *expr =
                nftnl_expr_alloc("meta");

        nftnl_expr_set_u32(expr, NFTNL_EXPR_META_DREG, reg);
        nftnl_expr_set_u32(expr, NFTNL_EXPR_META_KEY, key);

        nftnl_rule_add_expr(rule, expr);
}

static void add_expr_cmp(struct nftnl_rule *rule,
                         uint8_t reg,
                         uint8_t op,
                         uint32_t data)
{
        struct nftnl_expr *expr =
                nftnl_expr_alloc("cmp");

        nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_SREG, reg);
        nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_OP, op);
        nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_DATA, data);

        nftnl_rule_add_expr(rule, expr);
}

static void add_expr_exthdr(struct nftnl_rule *rule,
                            uint8_t reg,
                            uint8_t type,
                            uint8_t op,
                            uint32_t offset,
                            uint32_t len,
                            uint8_t flags)
{
        struct nftnl_expr *expr =
                nftnl_expr_alloc("exthdr");

        nftnl_expr_set_u32(expr, NFTNL_EXPR_EXTHDR_DREG, reg);
        nftnl_expr_set_u8(expr, NFTNL_EXPR_EXTHDR_TYPE, type);
        nftnl_expr_set_u32(expr, NFTNL_EXPR_EXTHDR_OP, op);
        nftnl_expr_set_u32(expr, NFTNL_EXPR_EXTHDR_OFFSET, offset);
        nftnl_expr_set_u32(expr, NFTNL_EXPR_EXTHDR_LEN, len);
        nftnl_expr_set_u32(expr, NFTNL_EXPR_EXTHDR_FLAGS, flags);

        nftnl_rule_add_expr(rule, expr);
}

static void add_expr_payload(struct nftnl_rule *rule,
                             uint8_t reg,
                             uint8_t base,
                             uint32_t offset,
                             uint32_t len)
{
        struct nftnl_expr *expr =
                nftnl_expr_alloc("payload");

        nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_DREG, reg);
        nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_BASE, base);
        nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_OFFSET, offset);
        nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_LEN, len);

        nftnl_rule_add_expr(rule, expr);
}


static void add_expr_queue(struct nftnl_rule *rule,
                           uint16_t queue)
{
        struct nftnl_expr *expr =
                nftnl_expr_alloc("queue");
        nftnl_expr_set_u16(expr, NFTNL_EXPR_QUEUE_NUM, queue);

        nftnl_rule_add_expr(rule, expr);
}

static struct nftnl_rule *create_rule(char const *const table,
                                      char const *const chain,
                                      uint64_t handle,
                                      uint32_t if_index,
                                      uint8_t key)
{

        struct nftnl_rule *r =
                nftnl_rule_alloc();

        nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, NFPROTO_INET);
        nftnl_rule_set_str(r, NFTNL_RULE_TABLE, table);
        nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, chain);
        nftnl_rule_set_u64(r, NFTNL_RULE_POSITION, handle);

        add_expr_meta(r, NFT_REG_1, key);
        add_expr_cmp(r, NFT_REG_1, NFT_CMP_EQ, if_index);

        add_expr_meta(r, NFT_REG_1, NFT_META_L4PROTO);
        add_expr_cmp(r, NFT_REG_1, NFT_CMP_EQ, IPPROTO_TCP);

        add_expr_exthdr(r,
                        NFT_REG_1,
                        TCPOPT_MPTCP,
                        NFT_EXTHDR_OP_TCPOPT,
                        0,
                        sizeof(uint8_t),
                        NFT_EXTHDR_F_PRESENT);
        
        add_expr_cmp(r, NFT_REG_1, NFT_CMP_EQ, true);

        add_expr_payload(r,
                         NFT_REG_1,
                         NFT_PAYLOAD_TRANSPORT_HEADER,
                         offsetof(struct tcphdr, th_flags),
                         sizeof(uint8_t));

        add_expr_cmp(r, NFT_REG_1, NFT_CMP_EQ, TH_SYN);

        add_expr_queue(r, NFT_QUEUE_NUM);

        return r;
}

static void add_rule(char const *const table,
                     char const *const chain,
                     uint64_t handle,
                     uint32_t if_index,
                     uint8_t key)
{
        L_AUTO_FREE_VAR(uint8_t *, buf) =
                l_malloc(MNL_SOCKET_BUFFER_SIZE);

        struct nftnl_rule *r =
                create_rule(table, chain, handle, if_index, key);

        uint32_t seq = time(NULL);

        struct mnl_nlmsg_batch *batch =
                mnl_nlmsg_batch_start(buf, MNL_SOCKET_BUFFER_SIZE);

        nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);

        uint32_t rule_seq = seq;

        //auto free
        struct nlmsghdr *nl = nftnl_rule_nlmsg_build_hdr(
                mnl_nlmsg_batch_current(batch),
                NFT_MSG_NEWRULE,
                NFPROTO_INET,
                NLM_F_APPEND | NLM_F_CREATE | NLM_F_ACK,
                seq++);

        nftnl_rule_nlmsg_build_payload(nl, r);
        nftnl_rule_free(r);
        mnl_nlmsg_batch_next(batch);

        nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);

        if (mnl_socket_sendto(so, 
                              mnl_nlmsg_batch_head(batch),
                              mnl_nlmsg_batch_size(batch)) < 0) {
                l_error("failed to send");
                return; //maybe return error
        }

        mnl_nlmsg_batch_stop(batch);

        ssize_t ret = mnl_socket_recvfrom(so,
                                          buf,
                                          MNL_SOCKET_BUFFER_SIZE);
        while (ret > 0) {
                ret = mnl_cb_run(buf, ret, rule_seq, portid, NULL, NULL);
                if (ret <= 0)
                        break;
                ret = mnl_socket_recvfrom(so,
                                          buf,
                                          MNL_SOCKET_BUFFER_SIZE);
        }

        if (ret == -1) {
                l_error("Error");
                return; //maybe return error
        }

        //maybe return success
}

static void add_table(char const *const table)
{
        L_AUTO_FREE_VAR(uint8_t *, buf) =
                l_malloc(MNL_SOCKET_BUFFER_SIZE);

        struct nftnl_table *t =
                nftnl_table_alloc();
        nftnl_table_set_u32(t, NFTNL_TABLE_FAMILY, NFPROTO_INET);
        nftnl_table_set_str(t, NFTNL_TABLE_NAME, table);

        uint32_t seq = time(NULL);

        struct mnl_nlmsg_batch *batch =
                mnl_nlmsg_batch_start(buf, MNL_SOCKET_BUFFER_SIZE);

        nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);

        uint32_t table_seq = seq;

        //auto free
        struct nlmsghdr *nl = nftnl_table_nlmsg_build_hdr(
                mnl_nlmsg_batch_current(batch),
                NFT_MSG_NEWTABLE,
                NFPROTO_INET,
                NLM_F_CREATE | NLM_F_ACK,
                seq++);

        nftnl_table_nlmsg_build_payload(nl, t);
        nftnl_table_free(t);
        mnl_nlmsg_batch_next(batch);

        nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);

        //always the same maybe separate it
        if (mnl_socket_sendto(so, 
                              mnl_nlmsg_batch_head(batch),
                              mnl_nlmsg_batch_size(batch)) < 0) {
                l_error("failed to send");
                return; //maybe return error
        }

        mnl_nlmsg_batch_stop(batch);

        ssize_t ret = mnl_socket_recvfrom(so,
                                          buf,
                                          MNL_SOCKET_BUFFER_SIZE);
        while (ret > 0) {
                ret = mnl_cb_run(buf, ret, table_seq, portid, NULL, NULL);
                if (ret <= 0)
                        break;
                ret = mnl_socket_recvfrom(so,
                                          buf,
                                          MNL_SOCKET_BUFFER_SIZE);
        }

        if (ret == -1) {
                l_error("Error");
                return; //maybe return error
        }

        //maybe return success
}

static void add_chain(char const *const table,
                      char const *const chain,
                      uint8_t hook)
{
        L_AUTO_FREE_VAR(uint8_t *, buf) =
                l_malloc(MNL_SOCKET_BUFFER_SIZE);

        struct nftnl_chain *c =
                nftnl_chain_alloc();
        nftnl_chain_set_u32(c, NFTNL_CHAIN_FAMILY, NFPROTO_INET);
        nftnl_chain_set_str(c, NFTNL_CHAIN_TABLE, table);
        nftnl_chain_set_str(c, NFTNL_CHAIN_NAME, chain);
        nftnl_chain_set_u32(c, NFTNL_CHAIN_HOOKNUM, hook);
        nftnl_chain_set_u32(c, NFTNL_CHAIN_PRIO, 0);

        uint32_t seq = time(NULL);

        struct mnl_nlmsg_batch *batch =
                mnl_nlmsg_batch_start(buf, MNL_SOCKET_BUFFER_SIZE);

        nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);

        uint32_t chain_seq = seq;

        //auto free
        struct nlmsghdr *nl = nftnl_chain_nlmsg_build_hdr(
                mnl_nlmsg_batch_current(batch),
                NFT_MSG_NEWCHAIN,
                NFPROTO_INET,
                NLM_F_CREATE | NLM_F_ACK,
                seq++);

        nftnl_chain_nlmsg_build_payload(nl, c);
        nftnl_chain_free(c);
        mnl_nlmsg_batch_next(batch);

        nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);

        //always the same maybe separate it
        if (mnl_socket_sendto(so, 
                              mnl_nlmsg_batch_head(batch),
                              mnl_nlmsg_batch_size(batch)) < 0) {
                l_error("failed to send");
                return; //maybe return error
        }

        mnl_nlmsg_batch_stop(batch);

        ssize_t ret = mnl_socket_recvfrom(so,
                                          buf,
                                          MNL_SOCKET_BUFFER_SIZE);
        while (ret > 0) {
                ret = mnl_cb_run(buf, ret, chain_seq, portid, NULL, NULL);
                if (ret <= 0)
                        break;
                ret = mnl_socket_recvfrom(so,
                                          buf,
                                          MNL_SOCKET_BUFFER_SIZE);
        }

        if (ret == -1) {
                l_error("Error");
                return; //maybe return error
        }

        //maybe return success
}

static void del_rule(char const *const table,
                     char const *const chain,
                     uint64_t handle)
{
        L_AUTO_FREE_VAR(uint8_t *, buf) =
                l_malloc(MNL_SOCKET_BUFFER_SIZE);

        struct nftnl_rule *r =
                nftnl_rule_alloc();

        nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, NFPROTO_INET);
        nftnl_rule_set_str(r, NFTNL_RULE_TABLE, table);
        nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, chain);
        nftnl_rule_set_u64(r, NFTNL_RULE_HANDLE, handle);

        uint32_t seq = time(NULL);

        struct mnl_nlmsg_batch *batch =
                mnl_nlmsg_batch_start(buf, MNL_SOCKET_BUFFER_SIZE);

        nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);

        uint32_t rule_seq = seq;

        //auto free
        struct nlmsghdr *nl = nftnl_rule_nlmsg_build_hdr(
                mnl_nlmsg_batch_current(batch),
                NFT_MSG_DELRULE,
                NFPROTO_INET,
                NLM_F_ACK,
                seq++);

        nftnl_rule_nlmsg_build_payload(nl, r);
        nftnl_rule_free(r);
        mnl_nlmsg_batch_next(batch);

        nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);

        if (mnl_socket_sendto(so, 
                              mnl_nlmsg_batch_head(batch),
                              mnl_nlmsg_batch_size(batch)) < 0) {
                l_error("failed to send");
                return; //maybe return error
        }

        mnl_nlmsg_batch_stop(batch);

        ssize_t ret = mnl_socket_recvfrom(so,
                                          buf,
                                          MNL_SOCKET_BUFFER_SIZE);
        while (ret > 0) {
                ret = mnl_cb_run(buf, ret, rule_seq, portid, NULL, NULL);
                if (ret <= 0)
                        break;
                ret = mnl_socket_recvfrom(so,
                                          buf,
                                          MNL_SOCKET_BUFFER_SIZE);
        }

        if (ret == -1) {
                l_error("Error");
                return; //maybe return error
        }

        //maybe return success
}

static void del_table(char const *const table)
{
        L_AUTO_FREE_VAR(uint8_t *, buf) =
                l_malloc(MNL_SOCKET_BUFFER_SIZE);

        struct nftnl_table *t =
                nftnl_table_alloc();
        nftnl_table_set_u32(t, NFTNL_TABLE_FAMILY, NFPROTO_INET);
        nftnl_table_set_str(t, NFTNL_TABLE_NAME, table);

        uint32_t seq = time(NULL);

        struct mnl_nlmsg_batch *batch =
                mnl_nlmsg_batch_start(buf, MNL_SOCKET_BUFFER_SIZE);

        nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);

        uint32_t table_seq = seq;

        //auto free
        struct nlmsghdr *nl = nftnl_table_nlmsg_build_hdr(
                mnl_nlmsg_batch_current(batch),
                NFT_MSG_DELTABLE,
                NFPROTO_INET,
                NLM_F_ACK,
                seq++);

        nftnl_table_nlmsg_build_payload(nl, t);
        nftnl_table_free(t);
        mnl_nlmsg_batch_next(batch);

        nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);

        //always the same maybe separate it
        if (mnl_socket_sendto(so, 
                              mnl_nlmsg_batch_head(batch),
                              mnl_nlmsg_batch_size(batch)) < 0) {
                l_error("failed to send");
                return; //maybe return error
        }

        mnl_nlmsg_batch_stop(batch);

        ssize_t ret = mnl_socket_recvfrom(so,
                                          buf,
                                          MNL_SOCKET_BUFFER_SIZE);
        while (ret > 0) {
                ret = mnl_cb_run(buf, ret, table_seq, portid, NULL, NULL);
                if (ret <= 0)
                        break;
                ret = mnl_socket_recvfrom(so,
                                          buf,
                                          MNL_SOCKET_BUFFER_SIZE);
        }

        if (ret == -1) {
                l_error("Error");
                return; //maybe return error
        }

        //maybe return success
}

static bool get_address_mask(char *mask, uint8_t *max_out)
{
	char *end;
	unsigned long mask_dec;

	mask_dec = strtoul(mask, &end, 10);

	if(end == mask || end == NULL || mask_dec > *max_out){
		return false;
	}

	*max_out = mask_dec;

	return true;
}

static bool add_network(struct net_queues *list, char *const network)
{
        char copy[64];
        l_strlcpy(copy, network, 64);
        char *mask = strchr(copy, '/');

        if (mask)
                *mask++ = '\0';

        struct net_mask *net_m = l_new(struct net_mask, 1);
        void *pointer;
        struct l_queue *queue;
        uint8_t family;
        if (strchr(network, '.')) { //ipv4

                family = AF_INET;
                pointer = &net_m->ipv4;
                net_m->mask = 32;
                queue = list->ipv4;

        }else if (strchr(network, ':')) { //ipv6

                family = AF_INET6;
                pointer = &net_m->ipv6;
                net_m->mask = 128;
                queue = list->ipv6;

        }else
                return false; //neither ipv4 nor ipv6

        if (!inet_pton(family, copy, pointer))
                return false;

        if (mask)
                if (!get_address_mask(mask, &net_m->mask)) 
                        return false;

        return l_queue_push_tail(queue, net_m);
}

static void parse_config_list(struct l_settings *settings, 
                              char const *group,
                              char const *key,
                              struct net_queues *queues)
{
        char **const list = l_settings_get_string_list(settings,
                                                       group,
                                                       key,
                                                       ',');

        if (l_strv_length(list)) {
                queues->ipv4 = l_queue_new();
                queues->ipv6 = l_queue_new();

                int index = 0;
                while (list[index]) {
                        add_network(queues, list[index]);
                        index++;
                }
        }

        l_strv_free(list);
}

static void parse_config_use_stun(struct l_settings *settings,
                                      char const *group)
{
        bool use_stun;
        if (l_settings_get_bool(settings,
                                group,
                                "use-stun",
                                &use_stun)) {

                config.use_stun = use_stun;
        }
}

static void parse_config_stun_server(struct l_settings *settings,
                                     char const *group)
{
        char *const stun_server = l_settings_get_string(settings,
                                                        group,
                                                        "stun-server");

        if (stun_server != NULL && strlen(stun_server) != 0)
                config.stun_server = stun_server;
}

static void parse_config_stun_port(struct l_settings *settings,
                                   char const *group)
{
        uint32_t port;
        if (l_settings_get_uint(settings, group, "stun-port", &port))
                if (port <= USHRT_MAX)
                        config.stun_port = port;
}

static void parse_config(struct l_settings *settings, void *user_data)
{
        (void) user_data;

        static char group[] = "core";

        parse_config_list(settings, group, "whitelist", &config.whitelist);

        parse_config_list(settings, group, "blacklist", &config.blacklist);

        parse_config_use_stun(settings, group);
        
        parse_config_stun_server(settings, group);

        parse_config_stun_port(settings, group);
}

static inline uint16_t calc_bit_mask(uint8_t mask_remainder)
{
        return ((2 << (mask_remainder - 1)) - 1) << (8 - mask_remainder);
}

static bool check_network_ipv6(struct l_queue *queue, struct in6_addr const *addr)
{
        uint8_t const *addr6 = addr->__in6_u.__u6_addr8;

        struct l_queue_entry const *entry =
                l_queue_get_entries(queue);

        while (entry) {

                struct net_mask *net_m = entry->data;

                uint8_t const *net_addr = net_m->ipv6.__in6_u.__u6_addr8;

		uint8_t mask_B = net_m->mask >> 3;
		uint8_t mask_remainder = net_m->mask & 0x7;

                //does not work
		if (!memcmp(addr6, net_addr, mask_B)) {
			if (mask_remainder) {

				uint16_t bit_mask = 
                                        calc_bit_mask(mask_remainder);

				if ((addr6[mask_B] & bit_mask) ==
                                    (net_addr[mask_B] & bit_mask))
					return true;

			} else 
				return true;
		}

                entry = entry->next;
        }

        return false;
}

static bool check_network_ipv4(struct l_queue *queue, struct in_addr const *addr)
{
        struct l_queue_entry const *entry =
                l_queue_get_entries(queue);

        while (entry) {
                struct net_mask *net_m = entry->data;

                uint32_t mask = (1UL << net_m->mask) - 1;

                if ((addr->s_addr & mask) == (net_m->ipv4.s_addr & mask))
                        return true;

                entry = entry->next;
        }

        return false;
}

static inline bool check_invalid_queue(struct l_queue *queue)
{
        return queue == NULL || l_queue_length(queue) == 0;
}

static bool elem_collision(struct l_queue *q1, struct l_queue *q2)
{
        struct l_queue_entry const *e1 =
                l_queue_get_entries(q1);

        struct l_queue_entry const *e2 =
                l_queue_get_entries(q2);

        while (e1) {
                struct net_mask *nm1 = e1->data;

                struct l_queue_entry const *e3 = e2;

                while (e3) {

                        struct net_mask *nm2 = e3->data;

                        if (!memcmp(nm1, nm2, sizeof(struct net_mask)))
                                return true;

                        e3 = e3->next;
                }

                e1 = e1->next;
        }

        return false;
}

static void do_flood(struct mptcpd_interface const *i,
                     struct sockaddr const *sa,
                     struct mptcpd_pm *pm,
                     flooding_function fun)
{
        struct l_queue_entry const *entry =
                l_queue_get_entries(i->addrs);

        while (entry) {

                struct sockaddr const *sa2 = entry->data;

                if (memcmp(sa2,
                           sa,
                           sizeof(struct sockaddr))) 
                        fun(name, i, sa2, pm);
                entry = entry->next;
        }

}

//ugllllly
static bool apply_check_ipv4(struct mptcpd_interface const *i,
                             struct sockaddr const *sa,
                             struct mptcpd_pm *pm,
                             struct in_addr *ipv4)
{
        struct pair *p;
        if (!l_queue_isempty(config.whitelist.ipv4)) { //has whitelist
                if (check_network_ipv4(config.whitelist.ipv4, ipv4)) { //has match whitelist
                        if (!check_network_ipv4(config.blacklist.ipv4, ipv4)) { // no blacklist or no match blacklist
                                if (!l_uintset_contains(whitelisted_ifs, i->index)) { // already flooded
                                        do_flood(i,
                                                 sa,
                                                 pm,
                                                 mptcpd_plugin_new_local_address_flow);  //rename them maybe

                                        l_uintset_put(whitelisted_ifs, i->index);

                                        p = l_hashmap_remove(ifs_handle, &i->index);
                                        if (p != NULL) {
                                                del_rule(NFT_TABLE_NAME, NFT_CHAIN_IN_NAME, p->handle_in);
                                                l_uintset_take(handles, p->handle_in);

                                                del_rule(NFT_TABLE_NAME,
                                                         NFT_CHAIN_OUT_NAME,
                                                         p->handle_out);
                                                l_uintset_take(handles, p->handle_out);

                                                l_free(p);
                                        }
                                }

                                return true;
                        } 

                        do_flood(i,
                                 sa,
                                 pm,
                                 mptcpd_plugin_delete_local_address_flow); //rename them maybe

                        l_uintset_put(blacklisted_ifs, i->index);

                        if (!l_hashmap_lookup(ifs_handle, &i->index)) {

                                p = l_new(struct pair, 1);

                                p->handle_in = l_uintset_find_unused_min(handles);

                                //check if error occurred
                                add_rule(NFT_TABLE_NAME,
                                         NFT_CHAIN_IN_NAME,
                                         p->handle_in,
                                         i->index,
                                         NFT_META_IIF);
                                
                                l_uintset_put(handles, p->handle_in);

                                p->handle_out = l_uintset_find_unused_min(handles);
                                
                                //check if error occurred
                                add_rule(NFT_TABLE_NAME,
                                         NFT_CHAIN_OUT_NAME,
                                         p->handle_out,
                                         i->index,
                                         NFT_META_OIF);

                                l_uintset_put(handles, p->handle_out);

                                l_hashmap_insert(ifs_handle, &i->index, p);
                        }
                }

                return false;
        }

        if (!l_queue_isempty(config.blacklist.ipv4) && //only has blacklist
            check_network_ipv4(config.blacklist.ipv4, ipv4)) {//has match blacklist
                do_flood(i,
                         sa,
                         pm,
                         mptcpd_plugin_delete_local_address_flow); //rename them maybe

                l_uintset_put(blacklisted_ifs, i->index);

                p = l_new(struct pair, 1);

                p->handle_in = l_uintset_find_unused_min(handles);

                //check if error occurred
                add_rule(NFT_TABLE_NAME,
                         NFT_CHAIN_IN_NAME,
                         p->handle_in,
                         i->index,
                         NFT_META_IIF);
                
                l_uintset_put(handles, p->handle_in);

                p->handle_out = l_uintset_find_unused_min(handles);
                
                //check if error occurred
                add_rule(NFT_TABLE_NAME,
                         NFT_CHAIN_OUT_NAME,
                         p->handle_out,
                         i->index,
                         NFT_META_OIF);

                l_uintset_put(handles, p->handle_out);

                l_hashmap_insert(ifs_handle, &i->index, p);

                return false;
        }

        return l_uintset_contains(whitelisted_ifs, i->index) ||
               l_queue_isempty(config.whitelist.ipv6);
}

//ugllllly x2
static bool apply_check_ipv6(struct mptcpd_interface const *i,
                             struct sockaddr const *sa,
                             struct mptcpd_pm *pm,
                             struct in6_addr *ipv6)
{
        struct pair *p;
        if (!l_queue_isempty(config.whitelist.ipv6)) { //has whitelist
                if (check_network_ipv6(config.whitelist.ipv6, ipv6)) { //has match whitelist
                        if (!check_network_ipv6(config.blacklist.ipv6, ipv6)) { // no blacklist or no match blacklist
                                if (!l_uintset_contains(whitelisted_ifs, i->index)) { // already flooded
                                        do_flood(i,
                                                 sa,
                                                 pm,
                                                 mptcpd_plugin_new_local_address_flow);  //rename them maybe

                                        l_uintset_put(whitelisted_ifs, i->index);

                                        p = l_hashmap_remove(ifs_handle, &i->index);
                                        if (p != NULL) {
                                                del_rule(NFT_TABLE_NAME, NFT_CHAIN_IN_NAME, p->handle_in);
                                                l_uintset_take(handles, p->handle_in);

                                                del_rule(NFT_TABLE_NAME,
                                                         NFT_CHAIN_OUT_NAME,
                                                         p->handle_out);
                                                l_uintset_take(handles, p->handle_out);

                                                l_free(p);
                                        }
                                }

                                return true;
                        } 

                        do_flood(i,
                                 sa,
                                 pm,
                                 mptcpd_plugin_delete_local_address_flow); //rename them maybe

                        l_uintset_put(blacklisted_ifs, i->index);
                        
                        if (!l_hashmap_lookup(ifs_handle, &i->index)) {

                                p = l_new(struct pair, 1);

                                p->handle_in = l_uintset_find_unused_min(handles);

                                //check if error occurred
                                add_rule(NFT_TABLE_NAME,
                                         NFT_CHAIN_IN_NAME,
                                         p->handle_in,
                                         i->index,
                                         NFT_META_IIF);
                                
                                l_uintset_put(handles, p->handle_in);

                                p->handle_out = l_uintset_find_unused_min(handles);
                                
                                //check if error occurred
                                add_rule(NFT_TABLE_NAME,
                                         NFT_CHAIN_OUT_NAME,
                                         p->handle_out,
                                         i->index,
                                         NFT_META_OIF);

                                l_uintset_put(handles, p->handle_out);

                                l_hashmap_insert(ifs_handle, &i->index, p);
                        }
                }

                return false;
        }

        if (!l_queue_isempty(config.blacklist.ipv6) && //only has blacklist
            check_network_ipv6(config.blacklist.ipv6, ipv6)) {//has match blacklist
                do_flood(i,
                         sa,
                         pm,
                         mptcpd_plugin_delete_local_address_flow); //rename them maybe

                l_uintset_put(blacklisted_ifs, i->index);
                
                p = l_new(struct pair, 1);

                p->handle_in = l_uintset_find_unused_min(handles);

                //check if error occurred
                add_rule(NFT_TABLE_NAME,
                         NFT_CHAIN_IN_NAME,
                         p->handle_in,
                         i->index,
                         NFT_META_IIF);
                
                l_uintset_put(handles, p->handle_in);

                p->handle_out = l_uintset_find_unused_min(handles);
                
                //check if error occurred
                add_rule(NFT_TABLE_NAME,
                         NFT_CHAIN_OUT_NAME,
                         p->handle_out,
                         i->index,
                         NFT_META_OIF);

                l_uintset_put(handles, p->handle_out);

                l_hashmap_insert(ifs_handle, &i->index, p);

                return false;
        }

        return l_uintset_contains(whitelisted_ifs, i->index) ||
               l_queue_isempty(config.whitelist.ipv4);
}

static uint32_t dummy_hash_func(void const *p)
{
        return *(uint32_t const *) p;
}

static int32_t dummy_compare_func(void const *a, void const *b)
{
        uint32_t index1 = *(uint32_t const *) a;
        uint32_t index2 = *(uint32_t const *) b;

        return index1 < index2 ? -1 : (index1 > index2 ? 1 : 0);
}

static void *dummy_key_copy_func(void const *p)
{
        uint32_t *key = l_new(uint32_t, 1);
        *key = *(uint32_t const *) p;

        return key;
}

// ----------------------------------------------------------------------

static bool net_check_new_interface(struct mptcpd_interface const *i,
                                    struct mptcpd_pm *pm)
{
        (void) pm;

        if (l_queue_isempty(config.whitelist.ipv4) &&
            l_queue_isempty(config.whitelist.ipv6))
            return true;

        struct pair *p = l_new(struct pair, 1);

        p->handle_in = l_uintset_find_unused_min(handles);

        //check if error occurred
        add_rule(NFT_TABLE_NAME,
                 NFT_CHAIN_IN_NAME,
                 p->handle_in,
                 i->index,
                 NFT_META_IIF);
        
        l_uintset_put(handles, p->handle_in);

        p->handle_out = l_uintset_find_unused_min(handles);
        
        //check if error occurred
        add_rule(NFT_TABLE_NAME,
                 NFT_CHAIN_OUT_NAME,
                 p->handle_out,
                 i->index,
                 NFT_META_OIF);

        l_uintset_put(handles, p->handle_out);

        l_hashmap_insert(ifs_handle, &i->index, p);

        return true;
}

static bool net_check_delete_interface(struct mptcpd_interface const *i,
                                       struct mptcpd_pm *pm)
{
        (void) pm;

        if (!l_uintset_take(whitelisted_ifs, i->index) ||
            l_uintset_take(blacklisted_ifs, i->index)) {

                struct pair *p = l_hashmap_remove(ifs_handle, &i->index);

                del_rule(NFT_TABLE_NAME, NFT_CHAIN_IN_NAME, p->handle_in);
                l_uintset_take(handles, p->handle_in);

                del_rule(NFT_TABLE_NAME,
                         NFT_CHAIN_OUT_NAME,
                         p->handle_out);
                l_uintset_take(handles, p->handle_out);

                l_free(p);
        }

        return true;
}

static bool net_check_new_local_address(struct mptcpd_interface const *i,
                                        struct sockaddr const *sa,
                                        struct mptcpd_pm *pm)
{
        (void) pm;

        l_info("New local address interface %u", i->index);
        
        if (l_uintset_contains(blacklisted_ifs, i->index))
                return false;

        l_info("Not blacklisted interface %u", i->index);

        if (l_uintset_contains(whitelisted_ifs, i->index) &&
            l_queue_isempty(config.blacklist.ipv4) &&
            l_queue_isempty(config.blacklist.ipv6))
                return true;

        l_info("Not whitelisted or with blacklist interface %u", i->index);

        if (sa->sa_family == AF_INET) {
                struct in_addr *addr_pointer;

                if (config.use_stun) {
                        struct in_addr addr;
                        if (!get_public_ipv4((char *) i->name, &addr)){
                                l_info("failed to get ip");
                                return false;
                        }
                        addr_pointer = &addr;
                } else 
                        addr_pointer = 
                                &((struct sockaddr_in *) sa)->sin_addr;

                return apply_check_ipv4(i, sa, pm, addr_pointer);
        }

        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) sa;

        return apply_check_ipv6(i, sa, pm, &sa6->sin6_addr);
}
 
static struct mptcpd_plugin_ops const pm_ops = {
        .delete_interface = net_check_delete_interface,
        .new_local_address = net_check_new_local_address,
};

static int net_check_init(struct mptcpd_pm *pm)
{
        (void) pm;

        //set up handler to read from queue and strip mptcp option

        mptcpd_plugin_read_config(name, parse_config, NULL);

        if (check_invalid_queue(config.whitelist.ipv4) &&
            check_invalid_queue(config.whitelist.ipv6) &&
            check_invalid_queue(config.blacklist.ipv4) &&
            check_invalid_queue(config.blacklist.ipv6)) {
                //l_error
                //clean
                return EXIT_FAILURE;
        }

        if (elem_collision(config.whitelist.ipv4, 
                           config.blacklist.ipv4) ||
            elem_collision(config.whitelist.ipv6,
                           config.blacklist.ipv6)) {
                //l_error
                //clean
                return EXIT_FAILURE;
        }

        if (config.use_stun && 
            (config.stun_server == NULL || 
             config.stun_port == 0)) {
                //l_error
                //clean
                return EXIT_FAILURE;
        }

        whitelisted_ifs = l_uintset_new(USHRT_MAX);
        blacklisted_ifs = l_uintset_new(USHRT_MAX);

        if (config.use_stun &&
            !stun_client_init(config.stun_server, config.stun_port)) {
                l_info("failed to init stun");
                return EXIT_FAILURE;
        }

        so = mnl_socket_open2(NETLINK_NETFILTER, SOCK_CLOEXEC);

        if (so == NULL) {
                l_error("failed open socket");
                return EXIT_FAILURE;
        }

        if (mnl_socket_bind(so, 0, MNL_SOCKET_AUTOPID)) {
                l_error("failed bind socket");
                return EXIT_FAILURE;
        }

        portid = mnl_socket_get_portid(so);

        ifs_handle = l_hashmap_new();

        if (!l_hashmap_set_hash_function(ifs_handle, dummy_hash_func) ||
            !l_hashmap_set_compare_function(ifs_handle,
                                            dummy_compare_func) ||
            !l_hashmap_set_key_copy_function(ifs_handle,
                                             dummy_key_copy_func) ||
            !l_hashmap_set_key_free_function(ifs_handle, l_free))
                return EXIT_FAILURE;

        handles = l_uintset_new_from_range(3, USHRT_MAX);

        add_table(NFT_TABLE_NAME);

        add_chain(NFT_TABLE_NAME, NFT_CHAIN_IN_NAME, NF_INET_LOCAL_IN);
        add_chain(NFT_TABLE_NAME, NFT_CHAIN_OUT_NAME, NF_INET_LOCAL_OUT);

        if (!mptcpd_plugin_register_ops(name, &pm_ops)) {
                l_error("Failed to initialize plugin '%s'.", name);
                //clean
                return EXIT_FAILURE;
        }
        
        l_info("MPTCP network check plugin started.");
        
        return EXIT_SUCCESS;
}

static void net_check_exit(struct mptcpd_pm *pm)
{
        (void) pm;

        del_table(NFT_TABLE_NAME);

        l_uintset_free(handles);

        l_hashmap_destroy(ifs_handle, l_free);

        mnl_socket_close(so);

        if (config.use_stun)
                stun_client_destroy();

        l_uintset_free(blacklisted_ifs);

        l_uintset_free(whitelisted_ifs);

        l_free(config.stun_server);

        l_queue_destroy(config.whitelist.ipv6, l_free);

        l_queue_destroy(config.whitelist.ipv4, l_free);

        l_info("MPTCP network check plugin exited.");
}

MPTCPD_PLUGIN_DEFINE(net_check,
                     "Network check plugin",
                     MPTCPD_PLUGIN_PRIORITY_HIGH,
                     net_check_init,
                     net_check_exit)

