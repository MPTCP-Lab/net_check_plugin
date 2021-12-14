#include <net_check/private/utils.h>

#include <libmnl/libmnl.h>

#include <ell/util.h>
#include <ell/log.h>

struct mnl_socket *init_socket(uint32_t *pid)
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
