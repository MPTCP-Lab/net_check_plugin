#include <limits.h>

#include <arpa/inet.h>

#include <ell/util.h>
#include <ell/log.h>
#include <ell/queue.h>
#include <ell/uintset.h>

#include <libnftnl/rule.h>

#include <libstuncli/libstuncli.h>

#include <linux/netfilter/nf_tables.h>

#include <net_check/private/types.h>
#include <net_check/private/config.h>
#include <net_check/private/rules.h>
#include <net_check/private/queue.h>

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

        if (!mptcpd_plugin_read_config(PLUGIN_NAME, parse_config, &config)) {
                l_error("couldn't load configuration");
                return EXIT_FAILURE;
        }

        if (!validate_conf(&config)) {
                l_error("invalid configuration");
                return EXIT_FAILURE;
        }

        whitelisted_ifs = l_uintset_new(USHRT_MAX);
        blacklisted_ifs = l_uintset_new(USHRT_MAX);
        ruled_ifs = l_uintset_new(USHRT_MAX);

        if (config.use_stun &&
            !stun_client_init(config.stun_server, config.stun_port)) {
                l_error("failed to init stun");
                return EXIT_FAILURE;
        }

        if (!init_queue())
                return EXIT_FAILURE;

        if (!init_rules())
                return EXIT_FAILURE;

        if (!mptcpd_plugin_register_ops(PLUGIN_NAME, &pm_ops)) {
                l_error("Failed to initialize plugin '%s'.", PLUGIN_NAME);
                return EXIT_FAILURE;
        }
        
        l_info("MPTCP network check plugin started.");
        
        return EXIT_SUCCESS;
}

static void net_check_exit(struct mptcpd_pm *pm)
{
        (void) pm;

        destroy_rules();

        destroy_queue();

        if (config.use_stun)
                stun_client_destroy();

        l_uintset_free(ruled_ifs);
        l_uintset_free(blacklisted_ifs);
        l_uintset_free(whitelisted_ifs);

        config_destroy(&config);

        l_info("MPTCP network check plugin exited.");
}

MPTCPD_PLUGIN_DEFINE(net_check,
                     "Network check plugin",
                     MPTCPD_PLUGIN_PRIORITY_HIGH,
                     net_check_init,
                     net_check_exit)

