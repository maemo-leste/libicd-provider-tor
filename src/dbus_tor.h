#ifndef __DBUS_TOR_H
#define __DBUS_TOR_H
#include "dbus_tor_shared.h"

int setup_tor_dbus(void *user_data);
int free_tor_dbus(void);

#if 0
void broadcast_status_changed(... status)
#endif
#endif
