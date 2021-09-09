#ifndef __LIBICD_TOR_H
#define __LIBICD_TOR_H

#include <glib.h>
#include "libicd_tor_shared.h"

/* libicd_tor.c */
gboolean get_system_wide_enabled(void);
char *generate_config(const char *config_name);
char *get_active_config(void);

#endif				/* __LIBICD_TOR_H */
