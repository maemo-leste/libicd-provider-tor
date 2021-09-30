#ifndef __LIBICD_TOR_H
#define __LIBICD_TOR_H

#include <glib.h>
#include "libicd_tor_shared.h"

gboolean config_is_known(const char *config_name);
gboolean config_has_transproxy(const char *config_name);
gboolean network_is_tor_provider(const char *network_id, char **ret_gconf_service_id);
gboolean get_system_wide_enabled(void);
char *generate_config(const char *config_name);
char *get_active_config(void);

#define TN_DEBUG(fmt, ...) ILOG_DEBUG(("[TOR NETWORK] "fmt), ##__VA_ARGS__)
#define TN_INFO(fmt, ...) ILOG_INFO(("[TOR NETWORK] " fmt), ##__VA_ARGS__)
#define TN_WARN(fmt, ...) ILOG_WARN(("[TOR NETWORK] %s.%d:" fmt), __func__, __LINE__, ##__VA_ARGS__)
#define TN_ERR(fmt, ...) ILOG_ERR(("[TOR NETWORK] %s.%d:" fmt), __func__, __LINE__, ##__VA_ARGS__)
#define TN_CRIT(fmt, ...) ILOG_CRIT(("[TOR NETWORK] %s.%d:" fmt), __func__, __LINE__, ##__VA_ARGS__)


#endif				/* __LIBICD_TOR_H */
