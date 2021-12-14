#ifndef ___NET_CHECK_UTILS_H___
#define ___NET_CHECK_UTILS_H___

#include <libmnl/libmnl.h>

struct mnl_socket *init_socket(uint32_t *pid);

#endif
