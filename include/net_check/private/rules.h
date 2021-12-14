#ifndef ___NET_CHECK_RULES_H___
#define ___NET_CHECK_RULES_H___

#include <stdint.h>

bool init_rules(void);

void destroy_rules(void);

void add_rule(char const *const table,
              char const *const chain,
              uint32_t if_index,
              uint16_t key);

void add_table(char const *const table);

void add_chain(char const *const table,
               char const *const chain,
               uint8_t hook);

void del_rule(char const *const table,
              char const *const chain,
              uint32_t index,
              uint16_t key);

void del_table(char const *const table);

#endif
