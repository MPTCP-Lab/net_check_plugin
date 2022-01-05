#include <net_check/private/types.h>
#include <net_check/private/utils.h>
#include <net_check/private/queue.h>

#include <stdlib.h>

#include <netinet//tcp.h>
#include <net/ethernet.h>

#include <linux/netfilter.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv6.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>

#include <ell/util.h>
#include <ell/log.h>
#include <ell/io.h>

static struct mnl_socket *sock = NULL;
static uint32_t pid;

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

                else if (tcpopt->kind == TCPOPT_MPTCP)
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

        if (mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0) {
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

        ssize_t ret = mnl_socket_recvfrom(sock,
                                          buf,
                                          MNL_SOCKET_BUFFER_SIZE);

        if (ret == -1) {
                l_error( "failed to read from queue");
                return false;
        }

        ret = mnl_cb_run(buf, ret, 0, pid, queue_cb, NULL);

        return ret > 0;
}

bool init_queue(void)
{
        sock = init_socket(&pid);

        if (sock == NULL)
                return false;

        uint8_t op = 1;
        mnl_socket_setsockopt(sock,
                              NETLINK_NO_ENOBUFS,
                              &op,
                              sizeof(ssize_t));

        L_AUTO_FREE_VAR(char *, buf) =
                l_malloc(MNL_SOCKET_BUFFER_SIZE);

        struct nlmsghdr *nl =
                nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, QUEUE_NUM);
        nfq_nlmsg_cfg_put_cmd(nl, AF_INET, NFQNL_CFG_CMD_BIND);

        if (mnl_socket_sendto(sock, nl, nl->nlmsg_len) < 0) {
                l_error("failed to bind to queue");
                return false;
        }

        nl = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, QUEUE_NUM);
        nfq_nlmsg_cfg_put_params(nl, NFQNL_COPY_PACKET, 0xffff);

        mnl_attr_put_u32(nl, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
        mnl_attr_put_u32(nl, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

        if (mnl_socket_sendto(sock, nl, nl->nlmsg_len) < 0) {
                l_error("failed to configure queue");
                return false;
        }

        struct l_io *io = l_io_new(mnl_socket_get_fd(sock));

        if (io == NULL) {
                l_error("failed add watcher to queue");
                return false;
        }

        //check ret
        l_io_set_close_on_destroy(io, true);
        l_io_set_read_handler(io, queue_handler, NULL, NULL);

        return true;
}

void destroy_queue(void)
{
        if (sock != NULL)
                mnl_socket_close(sock);
}
