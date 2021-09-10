#ifndef __LIBICD_TOR_H
#define __LIBICD_TOR_H

#include <glib.h>
#include "libicd_tor_shared.h"

gboolean config_is_known(const char* config_name);
gboolean network_is_tor_provider(const char* network_id, char **ret_gconf_service_id);
gboolean get_system_wide_enabled(void);
char *generate_config(const char *config_name);
char *get_active_config(void);

#endif				/* __LIBICD_TOR_H */
