#include <mptcpd/plugin.h>
#include <mptcpd/network_monitor.h>

#include <assert.h>
#include <stdlib.h>
#include <limits.h>

#include <arpa/inet.h>

#include <ell/util.h>
#include <ell/log.h>
#include <ell/queue.h>
#include <ell/settings.h>
#include <ell/strv.h>
#include <ell/uintset.h>

#include <libstuncli/libstuncli.h>

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

struct conf{
        struct net_queues whitelist;
        struct net_queues blacklist;
        bool check_public;
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
        .check_public = false,
        .stun_server = NULL,
        .stun_port = 0
};

struct l_uintset *success_ifs;

static char const name[] = "net_check";

// ----------------------------------------------------------------------

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

static void parse_config_check_public(struct l_settings *settings,
                                      char const *group)
{
        bool check_public;
        if (l_settings_get_bool(settings,
                                group,
                                "check-public",
                                &check_public)) {

                config.check_public = check_public;
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

        parse_config_check_public(settings, group);
        
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
        return queue == NULL || l_queue_length(queue);
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

// ----------------------------------------------------------------------

static bool net_check_new_local_address(struct mptcpd_interface const *i,
                                        struct sockaddr const *sa,
                                        struct mptcpd_pm *pm)
{
        (void) pm;

        if (l_uintset_contains(success_ifs, i->index))
                return true;

        bool check;
        if (sa->sa_family == AF_INET) {
                struct in_addr *addr_pointer;

                if (config.check_public) {
                        struct in_addr addr;
                        if (!get_public_ipv4((char *) i->name, &addr)){
                                l_info("failed to get ip");
                                return false;
                        }
                        addr_pointer = &addr;
                } else 
                        addr_pointer = 
                                &((struct sockaddr_in *) sa)->sin_addr;

                check = check_network_ipv4(config.whitelist.ipv4, 
                                           addr_pointer) &&
                        !check_network_ipv4(config.blacklist.ipv4,
                                            addr_pointer);

        } else {

                struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) sa;

                check = check_network_ipv6(config.whitelist.ipv6,
                                           &sa6->sin6_addr) &&
                        !check_network_ipv6(config.blacklist.ipv6,
                                            &sa6->sin6_addr);

        }
        
        if (check) {

                struct l_queue_entry const *entry =
                        l_queue_get_entries(i->addrs);

                while (entry) {

                        struct sockaddr const *sa2 = entry->data;

                        if (memcmp(sa2,
                                   sa,
                                   sizeof(struct sockaddr))) 
                                mptcpd_plugin_new_local_address_flow(name,
                                                                     i,
                                                                     sa2,
                                                                     pm);
                        entry = entry->next;
                }

                l_uintset_put(success_ifs, i->index);
        }

        return check;
}
 
static struct mptcpd_plugin_ops const pm_ops = {
        .new_local_address = net_check_new_local_address,
};

static int net_check_init(struct mptcpd_pm *pm)
{
        (void) pm;

        mptcpd_plugin_read_config(name, parse_config, NULL);

        if (check_invalid_queue(config.whitelist.ipv4) &&
            check_invalid_queue(config.whitelist.ipv6) &&
            check_invalid_queue(config.blacklist.ipv4) &&
            check_invalid_queue(config.blacklist.ipv6)) {
                //l_error
                //clean
                return -1;
        }

        if (elem_collision(config.whitelist.ipv4, 
                           config.blacklist.ipv4) ||
            elem_collision(config.whitelist.ipv6,
                           config.blacklist.ipv6)) {
                //l_error
                //clean
                return -1;
        }

        if (config.check_public && 
            (config.stun_server == NULL || 
             config.stun_port == 0)) {
                //l_error
                //clean
                return -1;
        }

        success_ifs = l_uintset_new(USHRT_MAX);

        if (config.check_public &&
            !stun_client_init(config.stun_server, config.stun_port)) {
                l_info("failed to init stun");
                return -1;
        }

        if (!mptcpd_plugin_register_ops(name, &pm_ops)) {
                l_error("Failed to initialize plugin '%s'.", name);
                //clean
                return -1;
        }
        
        l_info("MPTCP network check plugin started.");
        
        return 0;
}

static void net_check_exit(struct mptcpd_pm *pm)
{
        (void) pm;

        if (config.check_public)
                stun_client_destroy();

        l_uintset_free(success_ifs);

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

