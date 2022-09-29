#include <net_check/private/config.h>

#include <ell/util.h>
#include <ell/strv.h>
#include <ell/queue.h>
#include <ell/log.h>
#include <ell/settings.h>

#include <stdlib.h>
#include <limits.h>

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

void parse_config_list(struct l_settings const *settings, 
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

void parse_config_use_stun(struct l_settings *settings,
                           char const *group,
                           struct conf *config)
{
        bool use_stun;
        if (l_settings_get_bool(settings,
                                group,
                                "use-stun",
                                &use_stun)) {

                config->use_stun = use_stun;
        }
}

void parse_config_stun_server(struct l_settings const *settings,
                              char const *group,
                              struct conf *config)
{
        char *const stun_server = l_settings_get_string(settings,
                                                        group,
                                                        "server");

        if (stun_server != NULL && strlen(stun_server) != 0)
                config->stun_server = stun_server;
}

void parse_config_stun_port(struct l_settings const *settings,
                            char const *group,
                            struct conf *config)
{
        uint32_t port;
        if (l_settings_get_uint(settings, group, "port", &port))
                if (port <= USHRT_MAX)
                        config->stun_port = port;
}

void parse_config(struct l_settings const *settings, void *user_data)
{
        struct conf *config = user_data;

        static char core_group[] = "core";
        static char stun_group[] = "core";

        parse_config_list(settings,
                          core_group,
                          "whitelist",
                          &config->whitelist);

        parse_config_list(settings,
                          core_group,
                          "blacklist",
                          &config->blacklist);

        config->use_stun = l_settings_has_group(settings, stun_group);

        if (config->use_stun) {
                parse_config_stun_server(settings, stun_group, config);

                parse_config_stun_port(settings, stun_group, config);
        }
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

bool validate_conf(struct conf *config)
{
        if (check_invalid_queue(config->whitelist.ipv4) &&
            check_invalid_queue(config->whitelist.ipv6) &&
            check_invalid_queue(config->blacklist.ipv4) &&
            check_invalid_queue(config->blacklist.ipv6)) {
                l_error("no whitelist nor blacklist configured");
                return false;
        }

        if (elem_collision(config->whitelist.ipv4, 
                           config->blacklist.ipv4) ||
            elem_collision(config->whitelist.ipv6,
                           config->blacklist.ipv6)) {
                l_error("whitelist elements collide with blacklist "
                        "elements");
                return false;
        }

        if (config->use_stun && 
            (config->stun_server == NULL || 
             config->stun_port == 0)) {
                l_error("no stun server specified");
                return false;
        }

        return true;
}

void config_destroy(struct conf *config)
{
        if (config->stun_server)
                l_free(config->stun_server);

        l_queue_destroy(config->blacklist.ipv6, l_free);
        l_queue_destroy(config->whitelist.ipv6, l_free);

        l_queue_destroy(config->blacklist.ipv4, l_free);
        l_queue_destroy(config->whitelist.ipv4, l_free);
}
