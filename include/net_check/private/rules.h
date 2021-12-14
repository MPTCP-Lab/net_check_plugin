#ifndef ___NET_CHECK_RULES_H___
#define ___NET_CHECK_RULES_H___

#include <stdlib.h>
#include <stdint.h>

bool init_rules(void);

void destroy_rules(void);

ssize_t add_rule(char const *const table,
              char const *const chain,
              uint32_t if_index,
              uint16_t key);

ssize_t add_table(char const *const table);

ssize_t add_chain(char const *const table,
               char const *const chain,
               uint8_t hook);

ssize_t del_rule(char const *const table,
              char const *const chain,
              uint32_t index,
              uint16_t key);

ssize_t del_table(char const *const table);

#endif
