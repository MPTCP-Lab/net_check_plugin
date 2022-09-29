#ifndef ___NET_CHECK_CONFIG_H___
#define ___NET_CHECK_CONFIG_H___

#include "types.h"
#include <ell/settings.h>

void parse_config(struct l_settings const*settings, void *user_data);

bool validate_conf(struct conf *config);

void config_destroy(struct conf *config);

#endif
