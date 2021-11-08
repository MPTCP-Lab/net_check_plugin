#include <mptcpd/plugin.h>
#include <mptcpd/network_monitor.h>

#include <ell/util.h>
#include <ell/log.h>
#include <ell/queue.h>

#include <assert.h>

// ----------------------------------------------------------------------


// ----------------------------------------------------------------------

static void net_check_new_local_address(struct mptcpd_interface const *i,
                                        struct sockaddr const *sa,
                                        struct mptcpd_pm *pm)
{
        (void) pm;
        (void) i;
        (void) sa;
}
 
static void net_check_delete_local_address(struct mptcpd_interface const *i,
                                         struct sockaddr const *sa,
                                         struct mptcpd_pm *pm)
{
        (void) pm;
        (void) i;
        (void) sa;
}

static struct mptcpd_plugin_ops const pm_ops = {
        .new_local_address = net_check_new_local_address,
        .delete_local_address = net_check_delete_local_address
};

static int net_check_init(struct mptcpd_pm *pm)
{
        (void) pm;


        static char const name[] = "net_check";
        
        if (!mptcpd_plugin_register_ops(name, &pm_ops)) {
                l_error("Failed to initialize plugin '%s'.", name);
        
                return -1;
        }
        
        l_info("MPTCP network check plugin started.");
        
        return 0;
}

static void net_check_exit(struct mptcpd_pm *pm)
{
        (void) pm;


        l_info("MPTCP network check plugin exited.");
}

MPTCPD_PLUGIN_DEFINE(net_check,
                     "Network check plugin",
                     MPTCPD_PLUGIN_PRIORITY_HIGH,
                     net_check_init,
                     net_check_exit)

