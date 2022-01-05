#include <net_check/private/types.h>
#include <net_check/private/utils.h>
#include <net_check/private/rules.h>

#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

#include <stddef.h>
#include <time.h>

#include <ell/util.h>
#include <ell/log.h>

#include <netinet/tcp.h>

static struct mnl_socket *sock = NULL;
static uint32_t pid;

bool init_rules(void)
{
        sock = init_socket(&pid);

        if (sock == NULL)
                return false;

        add_table(PLUGIN_NAME);

        add_chain(PLUGIN_NAME, CHAIN_IN_NAME, NF_INET_LOCAL_IN);
        add_chain(PLUGIN_NAME, CHAIN_OUT_NAME, NF_INET_LOCAL_OUT);

        return true;
}

void destroy_rules(void)
{
        if (sock != NULL) {
                del_table(PLUGIN_NAME);

                mnl_socket_close(sock);
        }
}

static void add_expr_meta(struct nftnl_rule *rule,
                          uint8_t reg,
                          uint16_t key)
{
        struct nftnl_expr *expr =
                nftnl_expr_alloc("meta");

        if (expr == NULL) {
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

static ssize_t nft_recv(void *buf,
                        uint32_t seq,
                        mnl_cb_t fun,
                        void *data)
{
        ssize_t ret = mnl_socket_recvfrom(sock,
                                          buf,
                                          MNL_SOCKET_BUFFER_SIZE);
        while (ret > 0) {
                ret = mnl_cb_run(buf, ret, seq, pid, fun, data);

                if (ret <= MNL_CB_STOP)
                        break;

                ret = mnl_socket_recvfrom(sock,
                                          buf,
                                          MNL_SOCKET_BUFFER_SIZE);
        }

        return ret;
}

static ssize_t nft_send_batch(struct mnl_nlmsg_batch *batch,
                              void *buf,
                              uint32_t seq)
{
        if (mnl_socket_sendto(sock,
                              mnl_nlmsg_batch_head(batch),
                              mnl_nlmsg_batch_size(batch)) < 0) {
                l_error("failed to send");
                return -1; //maybe return error
        }

        mnl_nlmsg_batch_stop(batch);

        return nft_recv(buf, seq, NULL, NULL);
}

ssize_t add_rule(char const *const table,
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

        return nft_send_batch(batch, buf, rule_seq);
}

ssize_t add_table(char const *const table)
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

        return nft_send_batch(batch, buf, table_seq);
}

ssize_t add_chain(char const *const table,
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

        return nft_send_batch(batch, buf, chain_seq);
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

        if (mnl_socket_sendto(sock, nl, nl->nlmsg_len) < 0) {
                l_error("failed to send");
                return 0; //maybe return error
        }

        struct get_handle_data data = {
                .handle = 0,
                .index = index,
                .key = key
        };

        ssize_t ret = nft_recv(buf, seq, rule_cb, &data);

        if (ret == -1) {
                return 0; //maybe return error
        }

        return data.handle;
}

ssize_t del_rule(char const *const table,
                 char const *const chain,
                 uint32_t index,
                 uint16_t key)
{
        uint64_t handle = get_handle(table, chain, index, key);

        if (handle == 0)
                return -1;

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

        return nft_send_batch(batch, buf, rule_seq);
}

ssize_t del_table(char const *const table)
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

        return nft_send_batch(batch, buf, table_seq);
}
