#include <mptcpd/plugin.h>
#include <mptcpd/network_monitor.h>

#include <assert.h>
#include <stdlib.h>
#include <stddef.h>
#include <limits.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>

#include <ell/util.h>
#include <ell/log.h>
#include <ell/queue.h>
#include <ell/settings.h>
#include <ell/strv.h>
#include <ell/uintset.h>
#include <ell/hashmap.h>
#include <ell/io.h>

#include <libmnl/libmnl.h>

#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

#include <libstuncli/libstuncli.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv6.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>

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
        struct net_queues whitelist;
        struct net_queues blacklist;
        bool use_stun;
        char *stun_server;
        uint16_t stun_port;
};

static struct mnl_socket *so_rules;
static struct mnl_socket *so_queue;

static uint32_t portid_rules;
static uint32_t portid_queue;

static struct l_uintset *whitelisted_ifs;
static struct l_uintset *blacklisted_ifs;

static struct l_uintset *ruled_ifs;

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

// ----------------------------------------------------------------------

static void add_expr_meta(struct nftnl_rule *rule,
                          uint8_t reg,
                          uint16_t key)
{
        struct nftnl_expr *expr =
                nftnl_expr_alloc("meta");

        if (expr == NULL) {
                nftnl_rule_free(rule);
                l_error("failed to allocate rule expression");
                abort();
        }

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

        if (expr == NULL) {
                nftnl_rule_free(rule);
                l_error("failed to allocate rule expression");
                abort();
        }

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

        if (expr == NULL) {
                nftnl_rule_free(rule);
                l_error("failed to allocate rule expression");
                abort();
        }

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

        if (expr == NULL) {
                nftnl_rule_free(rule);
                l_error("failed to allocate rule expression");
                abort();
        }

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

        if (expr == NULL) {
                nftnl_rule_free(rule);
                l_error("failed to allocate rule expression");
                abort();
        }

        nftnl_expr_set_u16(expr, NFTNL_EXPR_QUEUE_NUM, queue);

        nftnl_rule_add_expr(rule, expr);
}

static struct nftnl_rule *create_rule(char const *const table,
                                      char const *const chain,
                                      uint32_t if_index,
                                      uint16_t key)
{
        struct nftnl_rule *r =
                nftnl_rule_alloc();

        if (r == NULL) {
                l_error("failed to allocate rule");
                abort();
        }

        nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, NFPROTO_INET);
        nftnl_rule_set_str(r, NFTNL_RULE_TABLE, table);
        nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, chain);

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

	add_expr_queue(r, QUEUE_NUM);

        return r;
}

static ssize_t nft_communication(void *buf,
                                 size_t len,
                                 uint32_t seq,
                                 mnl_cb_t fun,
                                 void *data)
{
        if (mnl_socket_sendto(so_rules, buf, len) < 0) {
                l_error("failed to send");
                return -1; //maybe return error
        }

        ssize_t ret = mnl_socket_recvfrom(so_rules,
                                          buf,
                                          MNL_SOCKET_BUFFER_SIZE);
        while (ret > 0) {
                ret = mnl_cb_run(buf, ret, seq, portid_rules, fun, data);
                if (ret <= 0)
                        break;
                ret = mnl_socket_recvfrom(so_rules,
                                          buf,
                                          MNL_SOCKET_BUFFER_SIZE);
        }

        return ret;
}

static void add_rule(char const *const table,
                     char const *const chain,
                     uint32_t if_index,
                     uint16_t key)
{
        L_AUTO_FREE_VAR(uint8_t *, buf) =
                l_malloc(MNL_SOCKET_BUFFER_SIZE);

        struct nftnl_rule *r =
                create_rule(table, chain, if_index, key);

        uint32_t seq = time(NULL);

        struct mnl_nlmsg_batch *batch =
                mnl_nlmsg_batch_start(buf, MNL_SOCKET_BUFFER_SIZE);

        if (batch == NULL) {
                nftnl_rule_free(r);
                l_error("failed to start batch");
                abort();
        }

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

        nft_communication(buf, nl->nlmsg_len, rule_seq, NULL, NULL);

        mnl_nlmsg_batch_stop(batch);

        //maybe return success or failure/error
}

static void add_table(char const *const table)
{
        L_AUTO_FREE_VAR(uint8_t *, buf) =
                l_malloc(MNL_SOCKET_BUFFER_SIZE);

        struct nftnl_table *t =
                nftnl_table_alloc();

        if (t == NULL) {
                l_error("failed to allocate table");
                abort();
        }

        nftnl_table_set_u32(t, NFTNL_TABLE_FAMILY, NFPROTO_INET);
        nftnl_table_set_str(t, NFTNL_TABLE_NAME, table);

        uint32_t seq = time(NULL);

        struct mnl_nlmsg_batch *batch =
                mnl_nlmsg_batch_start(buf, MNL_SOCKET_BUFFER_SIZE);

        if (batch == NULL) {
                nftnl_table_free(t);
                l_error("failed to start batch");
                abort();
        }

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

        nft_communication(buf, nl->nlmsg_len, table_seq, NULL, NULL);

        mnl_nlmsg_batch_stop(batch);

        //maybe return success or failure/error
}

static void add_chain(char const *const table,
                      char const *const chain,
                      uint8_t hook)
{
        L_AUTO_FREE_VAR(uint8_t *, buf) =
                l_malloc(MNL_SOCKET_BUFFER_SIZE);

        struct nftnl_chain *c =
                nftnl_chain_alloc();

        if (c == NULL) {
                l_error("failed to allocate chain");
                abort();
        }

        nftnl_chain_set_u32(c, NFTNL_CHAIN_FAMILY, NFPROTO_INET);
        nftnl_chain_set_str(c, NFTNL_CHAIN_TABLE, table);
        nftnl_chain_set_str(c, NFTNL_CHAIN_NAME, chain);
        nftnl_chain_set_u32(c, NFTNL_CHAIN_HOOKNUM, hook);
        nftnl_chain_set_u32(c, NFTNL_CHAIN_PRIO, 0);

        uint32_t seq = time(NULL);

        struct mnl_nlmsg_batch *batch =
                mnl_nlmsg_batch_start(buf, MNL_SOCKET_BUFFER_SIZE);

        if (batch == NULL) {
                nftnl_chain_free(c);
                l_error("failed to start batch");
                abort();
        }

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

        nft_communication(buf, nl->nlmsg_len, chain_seq, NULL, NULL);

        mnl_nlmsg_batch_stop(batch);

        //maybe return success or failure/error
}

static int rule_cb(const struct nlmsghdr *nl, void *user_data)
{
	struct nftnl_rule *r;
	struct get_handle_data *data = user_data;

	r = nftnl_rule_alloc();
        if (r == NULL) {
                l_error("failed to allocate rule");
                abort();
        }

	if (nftnl_rule_nlmsg_parse(nl, r) < 0) {
                nftnl_rule_free(r);
		return MNL_CB_ERROR;
	}

        struct nftnl_expr_iter *expr_it =
                nftnl_expr_iter_create(r);
        if (expr_it == NULL) {
                nftnl_rule_free(r);
                l_error("failed to allocate rule expression iterator");
                abort();
        }

        struct nftnl_expr *expr =
                nftnl_expr_iter_next(expr_it);

        expr = nftnl_expr_iter_next(expr_it);

        if (nftnl_expr_get_u32(expr, NFTNL_EXPR_CMP_DATA) == data->index)
                data->handle = nftnl_rule_get_u64(r, NFTNL_RULE_HANDLE);

        nftnl_expr_iter_destroy(expr_it);

	nftnl_rule_free(r);
	return MNL_CB_OK;
}

static uint64_t get_handle(char const *const table,
                           char const *const chain,
                           uint32_t index,
                           uint16_t key)
{
        L_AUTO_FREE_VAR(char *, buf) =
                l_malloc(MNL_SOCKET_BUFFER_SIZE);

        struct nftnl_rule *r =
                nftnl_rule_alloc();

        if (r == NULL) {
                l_error("failed to allocate rule");
                abort();
        }

        nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, NFPROTO_INET);
        nftnl_rule_set_str(r, NFTNL_RULE_TABLE, table);
        nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, chain);

        uint32_t seq = time(NULL);

        struct nlmsghdr *nl = nftnl_rule_nlmsg_build_hdr(
                buf,
                NFT_MSG_GETRULE,
                NFPROTO_INET,
                NLM_F_DUMP,
                seq);
        
        nftnl_rule_nlmsg_build_payload(nl, r);
        nftnl_rule_free(r);

        struct get_handle_data data = {
                .handle = 0,
                .index = index,
                .key = key
        };

        ssize_t ret = nft_communication(buf,
                                        nl->nlmsg_len,
                                        seq,
                                        rule_cb,
                                        &data);

        if (ret == -1) {
                return 0; //maybe return error
        }

        return data.handle;
}

static void del_rule(char const *const table,
                     char const *const chain,
                     uint32_t index,
                     uint16_t key)
{

        uint64_t handle = get_handle(table, chain, index, key);

        if (handle == 0)
                return;

        L_AUTO_FREE_VAR(uint8_t *, buf) =
                l_malloc(MNL_SOCKET_BUFFER_SIZE);

        struct nftnl_rule *r =
                nftnl_rule_alloc();

        if (r == NULL) {
                l_error("failed to allocate rule");
                abort();
        }

        nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, NFPROTO_INET);
        nftnl_rule_set_str(r, NFTNL_RULE_TABLE, table);
        nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, chain);
        nftnl_rule_set_u64(r, NFTNL_RULE_HANDLE, handle);

        uint32_t seq = time(NULL);

        struct mnl_nlmsg_batch *batch =
                mnl_nlmsg_batch_start(buf, MNL_SOCKET_BUFFER_SIZE);

        if (batch == NULL) {
                nftnl_rule_free(r);
                l_error("failed to start batch");
                abort();
        }

        nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);

        uint32_t rule_seq = seq;

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

        nft_communication(buf, nl->nlmsg_len, rule_seq, NULL, NULL);

        mnl_nlmsg_batch_stop(batch);

        //maybe return success or failure/error
}

static void del_table(char const *const table)
{
        L_AUTO_FREE_VAR(uint8_t *, buf) =
                l_malloc(MNL_SOCKET_BUFFER_SIZE);

        struct nftnl_table *t =
                nftnl_table_alloc();

        if (t == NULL) {
                l_error("failed to allocate table");
                abort();
        }

        nftnl_table_set_u32(t, NFTNL_TABLE_FAMILY, NFPROTO_INET);
        nftnl_table_set_str(t, NFTNL_TABLE_NAME, table);

        uint32_t seq = time(NULL);

        struct mnl_nlmsg_batch *batch =
                mnl_nlmsg_batch_start(buf, MNL_SOCKET_BUFFER_SIZE);

        if (batch == NULL) {
                nftnl_table_free(t);
                l_error("failed to start batch");
                abort();
        }

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

        nft_communication(buf, nl->nlmsg_len, table_seq, NULL, NULL);

        mnl_nlmsg_batch_stop(batch);

        //maybe return success or failure/error
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

        parse_config_list(settings,
                          group,
                          "whitelist",
                          &config.whitelist);

        parse_config_list(settings,
                          group,
                          "blacklist",
                          &config.blacklist);

        parse_config_use_stun(settings, group);
        
        parse_config_stun_server(settings, group);

        parse_config_stun_port(settings, group);
}

static void config_destroy(void)
{
        l_free(config.stun_server);

        l_queue_destroy(config.blacklist.ipv6, l_free);
        l_queue_destroy(config.whitelist.ipv4, l_free);

        l_queue_destroy(config.blacklist.ipv6, l_free);
        l_queue_destroy(config.whitelist.ipv4, l_free);
}

static inline uint16_t calc_bit_mask(uint8_t mask_remainder)
{
        return ((2 << (mask_remainder - 1)) - 1) << (8 - mask_remainder);
}

static bool check_network_ipv6(struct l_queue *queue,
                               struct in6_addr const *addr)
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

static bool check_network_ipv4(struct l_queue *queue,
                               struct in_addr const *addr)
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
                        fun(PLUGIN_NAME, i, sa2, pm);
                entry = entry->next;
        }

}

static void allow_mptcp(struct mptcpd_interface const *i,
                        struct sockaddr const *sa,
                        struct mptcpd_pm *pm)
{
        if (!l_uintset_contains(whitelisted_ifs, i->index)) {
                do_flood(i,
                         sa,
                         pm,
                         mptcpd_plugin_new_local_address_flow);

                l_uintset_put(whitelisted_ifs, i->index);

                if (l_uintset_contains(ruled_ifs, i->index)) {
                        del_rule(PLUGIN_NAME,
                                 CHAIN_IN_NAME,
                                 i->index,
                                 NFT_META_IIF);

                        del_rule(PLUGIN_NAME,
                                 CHAIN_OUT_NAME,
                                 i->index,
                                 NFT_META_OIF);

                        l_uintset_take(ruled_ifs, i->index);
                }
        }
}

static void block_mptcp(struct mptcpd_interface const *i,
                        struct sockaddr const *sa,
                        struct mptcpd_pm *pm,
                        bool to_insert)
{
        do_flood(i,
                 sa,
                 pm,
                 mptcpd_plugin_delete_local_address_flow);

        if (to_insert)
                l_uintset_put(blacklisted_ifs, i->index);

        if (!l_uintset_contains(ruled_ifs, i->index)) {
                //check if error occurred
                add_rule(PLUGIN_NAME,
                         CHAIN_IN_NAME,
                         i->index,
                         NFT_META_IIF);

                //check if error occurred
                add_rule(PLUGIN_NAME,
                         CHAIN_OUT_NAME,
                         i->index,
                         NFT_META_OIF);

                l_uintset_put(ruled_ifs, i->index);
        }
}

//can probably be simplified
static bool apply_check_ipv4(struct mptcpd_interface const *i,
                             struct sockaddr const *sa,
                             struct mptcpd_pm *pm,
                             struct in_addr *ipv4)
{
        if (!l_queue_isempty(config.whitelist.ipv4)) {

                bool blacklisted =
                        check_network_ipv4(config.blacklist.ipv4, ipv4);

                if (check_network_ipv4(config.whitelist.ipv4, ipv4) &&
                    !blacklisted) {
                        
                        allow_mptcp(i, sa, pm);

                        return true;
                } 

                block_mptcp(i, sa, pm, blacklisted);

                return false;
        }

        if (!l_queue_isempty(config.blacklist.ipv4) &&
            check_network_ipv4(config.blacklist.ipv4, ipv4)) {
                block_mptcp(i, sa, pm, true);

                return false;
        }

        return l_uintset_contains(whitelisted_ifs, i->index) ||
               l_queue_isempty(config.whitelist.ipv6);
}

//can probably be simplified
static bool apply_check_ipv6(struct mptcpd_interface const *i,
                             struct sockaddr const *sa,
                             struct mptcpd_pm *pm,
                             struct in6_addr *ipv6)
{
        if (!l_queue_isempty(config.whitelist.ipv6)) {
                bool blacklisted =
                        check_network_ipv6(config.blacklist.ipv6, ipv6);

                if (check_network_ipv6(config.whitelist.ipv6, ipv6) &&
                    !blacklisted) {
                        
                        allow_mptcp(i, sa, pm);

                        return true;
                } 

                block_mptcp(i, sa, pm, blacklisted);

                return false;
        }

        if (!l_queue_isempty(config.blacklist.ipv6) &&
            check_network_ipv6(config.blacklist.ipv6, ipv6)) {
                block_mptcp(i, sa, pm, true);

                return false;
        }

        return l_uintset_contains(whitelisted_ifs, i->index) ||
               l_queue_isempty(config.whitelist.ipv4);
}

static bool strip_mptcp(struct pkt_buff *pkt, uint8_t family)
{
        void *pointer;
        if (family == AF_INET) {
                pointer = nfq_ip_get_hdr(pkt);
                nfq_ip_set_transport_header(pkt, pointer);
        } else {
                pointer = nfq_ip6_get_hdr(pkt);
                nfq_ip6_set_transport_header(pkt,
                                             pointer,
                                             (uint8_t) IPPROTO_TCP);
        }

        struct tcphdr *tcph = nfq_tcp_get_hdr(pkt);

        if (tcph == NULL)
                return false;

        uint8_t *options = (uint8_t *) tcph + sizeof(struct tcphdr);

        struct tcpoption *tcpopt = (struct tcpoption *) options;

        while (options) {
                if (tcpopt->kind == TCPOPT_EOL)
                        return false;

                else if (tcpopt->kind == 30)
                        break;

                else if (tcpopt->kind == TCPOPT_NOP)
                        options++;

                else
                        options += tcpopt->length;

                tcpopt = (struct tcpoption *) options;
        }

        uint16_t offset = options - (uint8_t *) tcph;

        char const nop[4] = {1,1,1,1};

        uint16_t ip_len = (uint8_t *) tcph - (uint8_t *) pointer;

        if (family == AF_INET) {
                nfq_ip_mangle(pkt,
                              ip_len,
                              offset,
                              tcpopt->length,
                              nop,
                              tcpopt->length);
                nfq_tcp_compute_checksum_ipv4(tcph, pointer);
        }else {
                nfq_ip6_mangle(pkt,
                               ip_len,
                               offset,
                               tcpopt->length,
                               nop,
                               tcpopt->length);
                nfq_tcp_compute_checksum_ipv6(tcph, pointer);
        }

        return true;
}

static int send_verdict(struct nlmsghdr const *nl,
                        struct nfqnl_msg_packet_hdr const *ph,
                        struct pkt_buff *pkt)
{
        L_AUTO_FREE_VAR(char *, buf) =
                l_malloc(MNL_SOCKET_BUFFER_SIZE);

        struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nl);
        struct nlmsghdr *nlh = nfq_nlmsg_put(buf,
                                             NFQNL_MSG_VERDICT,
                                             ntohs(nfg->res_id));

        nfq_nlmsg_verdict_put(nlh, ntohl(ph->packet_id), NF_ACCEPT);
        nfq_nlmsg_verdict_put_pkt(nlh, pktb_data(pkt), pktb_len(pkt));
        pktb_free(pkt);

        if (mnl_socket_sendto(so_queue, nlh, nlh->nlmsg_len) < 0) {
                l_error("failed to send verdict");
                return MNL_CB_ERROR;
        }

        return MNL_CB_OK;
}

static int queue_cb(struct nlmsghdr const *nl, void *data)
{
        (void) data;

        struct nlattr *attr[NFQA_MAX + 1] = {0};

        if (nfq_nlmsg_parse(nl, attr) < 0) {
                l_error("failed to parse attributes");
                return MNL_CB_ERROR;
        }

        if (attr[NFQA_PACKET_HDR] == NULL || attr[NFQA_PAYLOAD] == NULL) {
                l_error("invalid queue packet");
                return MNL_CB_ERROR;
        }

        struct nfqnl_msg_packet_hdr *ph =
                mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);

        uint16_t proto = ntohs(ph->hw_protocol);
        uint8_t family = AF_UNSPEC;

        if (proto == ETHERTYPE_IP)
                family = AF_INET;

        else if (proto == ETHERTYPE_IPV6)
                family = AF_INET6;

        else {
                l_error("invalid protocol received");
                return MNL_CB_ERROR;
        }

        void *payload = mnl_attr_get_payload(attr[NFQA_PAYLOAD]);
        uint16_t plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);

        struct pkt_buff *pkt = pktb_alloc(family, payload, plen, 0xff);

        if (pkt == NULL) {
                l_error("failed to allocate packet buffer");
                abort();
        }

        if (!strip_mptcp(pkt, family)) {
                pktb_free(pkt);
                return MNL_CB_ERROR;
        }

        return send_verdict(nl, ph, pkt);
}

static bool queue_handler(struct l_io *io, void *user_data)
{
        (void) user_data;
        (void) io;

        L_AUTO_FREE_VAR(char *, buf) =
                l_malloc(MNL_SOCKET_BUFFER_SIZE);

        ssize_t ret = mnl_socket_recvfrom(so_queue,
                                          buf,
                                          MNL_SOCKET_BUFFER_SIZE);

        if (ret == -1) {
                l_error( "failed to read from queue");
                return false;
        }

        ret = mnl_cb_run(buf, ret, 0, portid_queue, queue_cb, NULL);

        return ret > 0;
}

static struct mnl_socket *init_socket(uint32_t *pid)
{
        struct mnl_socket *sock =
                mnl_socket_open2(NETLINK_ROUTE, SOCK_CLOEXEC);

        if (sock == NULL){
                l_error("failed to open socket netlink");
                return NULL;
        }

        if (mnl_socket_bind(sock, 0, MNL_SOCKET_AUTOPID) < 0) {
                l_error("failed to bind socket netlink");
                mnl_socket_close(sock);
                return NULL;
        }

        *pid = mnl_socket_get_portid(sock);

        return sock;
}

static bool setup_so_queue(void)
{
        so_queue = init_socket(&portid_queue);

        if (so_queue == NULL)
                return false;

        uint8_t op = 1;
        mnl_socket_setsockopt(so_queue,
                              NETLINK_NO_ENOBUFS,
                              &op,
                              sizeof(ssize_t));

        L_AUTO_FREE_VAR(char *, buf) =
                l_malloc(MNL_SOCKET_BUFFER_SIZE);

        struct nlmsghdr *nl =
                nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, QUEUE_NUM);
        nfq_nlmsg_cfg_put_cmd(nl, AF_INET, NFQNL_CFG_CMD_BIND);

        if (mnl_socket_sendto(so_queue, nl, nl->nlmsg_len) < 0) {
                l_error("failed to bind to queue");
                return false;
        }

        nl = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, QUEUE_NUM);
        nfq_nlmsg_cfg_put_params(nl, NFQNL_COPY_PACKET, 0xffff);

        mnl_attr_put_u32(nl, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
        mnl_attr_put_u32(nl, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

        if (mnl_socket_sendto(so_queue, nl, nl->nlmsg_len) < 0) {
                l_error("failed to configure queue");
                return false;
        }

        struct l_io *io = l_io_new(mnl_socket_get_fd(so_queue));

        if (io == NULL) {
                l_error("failed add watcher to queue");
                return false;
        }

        //check ret
        l_io_set_close_on_destroy(io, true);
        l_io_set_read_handler(io, queue_handler, NULL, NULL);

        return true;
}

static bool validate_conf(void)
{
        if (check_invalid_queue(config.whitelist.ipv4) &&
            check_invalid_queue(config.whitelist.ipv6) &&
            check_invalid_queue(config.blacklist.ipv4) &&
            check_invalid_queue(config.blacklist.ipv6)) {
                l_error("no whitelist nor blacklist configured");
                return false;
        }

        if (elem_collision(config.whitelist.ipv4, 
                           config.blacklist.ipv4) ||
            elem_collision(config.whitelist.ipv6,
                           config.blacklist.ipv6)) {
                l_error("whitelist elements collide with blacklist "
                        "elements");
                return false;
        }

        if (config.use_stun && 
            (config.stun_server == NULL || 
             config.stun_port == 0)) {
                l_error("no stun server specified");
                return false;
        }

        return true;
}

// ----------------------------------------------------------------------

static bool net_check_new_interface(struct mptcpd_interface const *i,
                                    struct mptcpd_pm *pm)
{
        (void) pm;

        if (l_queue_isempty(config.whitelist.ipv4) &&
            l_queue_isempty(config.whitelist.ipv6))
            return true;

        //check if error occurred
        add_rule(PLUGIN_NAME,
                 CHAIN_IN_NAME,
                 i->index,
                 NFT_META_IIF);
        
        //check if error occurred
        add_rule(PLUGIN_NAME,
                 CHAIN_OUT_NAME,
                 i->index,
                 NFT_META_OIF);

        l_uintset_put(ruled_ifs, i->index);

        return true;
}

static bool net_check_delete_interface(struct mptcpd_interface const *i,
                                       struct mptcpd_pm *pm)
{
        (void) pm;

        if (l_uintset_contains(ruled_ifs, i->index)){

                del_rule(PLUGIN_NAME,
                         CHAIN_IN_NAME,
                         i->index,
                         NFT_META_IIF);

                del_rule(PLUGIN_NAME,
                         CHAIN_OUT_NAME,
                         i->index,
                         NFT_META_OIF);

                l_uintset_take(ruled_ifs, i->index);
        }

        return true;
}

static bool net_check_new_local_address(struct mptcpd_interface const *i,
                                        struct sockaddr const *sa,
                                        struct mptcpd_pm *pm)
{
        (void) pm;

        if (l_uintset_contains(blacklisted_ifs, i->index))
                return false;

        if (l_uintset_contains(whitelisted_ifs, i->index) &&
            l_queue_isempty(config.blacklist.ipv4) &&
            l_queue_isempty(config.blacklist.ipv6))
                return true;

        if (sa->sa_family == AF_INET) {
                struct in_addr *addr_pointer;

                if (config.use_stun) {
                        struct in_addr addr;
                        if (!get_public_ipv4((char *) i->name, &addr)) {
                                l_error("failed to get public ip");
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
        .new_interface = net_check_new_interface,
        .delete_interface = net_check_delete_interface,
        .new_local_address = net_check_new_local_address,
};

static int net_check_init(struct mptcpd_pm *pm)
{
        (void) pm;

        if (!mptcpd_plugin_read_config(PLUGIN_NAME, parse_config, NULL))
                return EXIT_FAILURE;

        if (!validate_conf())
                goto err_conf;

        whitelisted_ifs = l_uintset_new(USHRT_MAX);
        blacklisted_ifs = l_uintset_new(USHRT_MAX);
        ruled_ifs = l_uintset_new(USHRT_MAX);

        if (config.use_stun &&
            !stun_client_init(config.stun_server, config.stun_port)) {
                l_info("failed to init stun");
                goto err_sets;
        }

        if (!setup_so_queue())
                goto err_stun;

        so_rules = init_socket(&portid_rules);

        if (so_rules == NULL)
                goto err_sock;

        add_table(PLUGIN_NAME);

        add_chain(PLUGIN_NAME, CHAIN_IN_NAME, NF_INET_LOCAL_IN);
        add_chain(PLUGIN_NAME, CHAIN_OUT_NAME, NF_INET_LOCAL_OUT);

        if (!mptcpd_plugin_register_ops(PLUGIN_NAME, &pm_ops)) {
                l_error("Failed to initialize plugin '%s'.", PLUGIN_NAME);
                goto err_full;
        }
        
        l_info("MPTCP network check plugin started.");
        
        return EXIT_SUCCESS;

err_full:
        del_table(PLUGIN_NAME);
        mnl_socket_close(so_rules);

err_sock:
        mnl_socket_close(so_queue);

err_stun:
        if (config.use_stun)
                stun_client_destroy();

err_sets:
        l_uintset_free(ruled_ifs);
        l_uintset_free(blacklisted_ifs);
        l_uintset_free(whitelisted_ifs);

err_conf:
        config_destroy();

        return EXIT_FAILURE;
}

static void net_check_exit(struct mptcpd_pm *pm)
{
        (void) pm;

        del_table(PLUGIN_NAME);

        mnl_socket_close(so_rules);

        mnl_socket_close(so_queue);

        if (config.use_stun)
                stun_client_destroy();

        l_uintset_free(ruled_ifs);
        l_uintset_free(blacklisted_ifs);
        l_uintset_free(whitelisted_ifs);

        config_destroy();

        l_info("MPTCP network check plugin exited.");
}

MPTCPD_PLUGIN_DEFINE(net_check,
                     "Network check plugin",
                     MPTCPD_PLUGIN_PRIORITY_HIGH,
                     net_check_init,
                     net_check_exit)

