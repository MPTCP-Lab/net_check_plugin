#ifndef ___NET_CHECK_CONFIG_H___
#define ___NET_CHECK_CONFIG_H___

#include "types.h"
#include <ell/settings.h>

void parse_config_list(struct l_settings *settings, 
                       char const *group,
                       char const *key,
                       struct net_queues *queues);


void parse_config_use_stun(struct l_settings *settings,
                           char const *group,
                           struct conf *config);

void parse_config_stun_server(struct l_settings *settings,
                              char const *group,
                              struct conf *config);

void parse_config_stun_port(struct l_settings *settings,
                            char const *group,
                            struct conf *config);

void parse_config(struct l_settings *settings, void *user_data);

bool validate_conf(struct conf *config);

void config_destroy(struct conf *config);

#endif
