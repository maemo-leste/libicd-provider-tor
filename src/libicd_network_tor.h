#ifndef __LIBICD_NETWORK_TOR_H
#define __LIBICD_NETWORK_TOR_H
#include <string.h>
#include <stdio.h>
#include <glib.h>
#include <gconf/gconf-client.h>
#include <pwd.h>

#include <osso-ic-gconf.h>
#include "icd/support/icd_log.h"
#include <network_api.h>

#include "dbus_tor.h"
#include "libicd_tor.h"

struct _network_tor_state {
	/* State data here, since without IAP we do not have tor_network_data */
	gboolean system_wide_enabled;
	gchar *active_config;
	gboolean iap_connected;

	gboolean tor_running;
	gboolean tor_bootstrapped_running;
	gboolean tor_bootstrapped;
#if 0
	gboolean network_is_tor_service_provider;
#endif
#if 0
	gboolean manual_start_requested;
	gboolean manual_stop_requested;
#endif
};
typedef struct _network_tor_state network_tor_state;

struct _network_tor_private {
	/* For pid monitoring */
	icd_nw_watch_pid_fn watch_cb;
	gpointer watch_cb_token;

	icd_nw_close_fn close_cb;

#if 0
	icd_srv_limited_conn_fn limited_conn_fn;
#endif

	GSList *network_data_list;

	GConfClient *gconf_client;
	guint gconf_cb_id_systemwide;

	network_tor_state state;
};
typedef struct _network_tor_private network_tor_private;

struct _tor_network_data {
	network_tor_private *private;

	icd_nw_ip_up_cb_fn ip_up_cb;
	gpointer ip_up_cb_token;

	icd_nw_ip_down_cb_fn ip_down_cb;
	gpointer ip_down_cb_token;

	/* Tor pid */
	pid_t tor_pid;

	/* Tor command auth pw/token */
	char *tor_stem_auth;

	/* "Wait for Tor" stem script */
	pid_t wait_for_tor_pid;

	/* For matching / callbacks later on (like close and limited_conn callback) */
	gchar *network_type;
	guint network_attrs;
	gchar *network_id;
};
typedef struct _tor_network_data tor_network_data;

gboolean icd_nw_init(struct icd_nw_api *network_api,
		     icd_nw_watch_pid_fn watch_fn, gpointer watch_fn_token,
		     icd_nw_close_fn close_fn,
		     icd_nw_status_change_fn status_change_fn,
		     icd_nw_renew_fn renew_fn);

/* Helpers */
void network_stop_all(tor_network_data * network_data);
void network_free_all(tor_network_data * network_data);
pid_t spawn_as(const char *username, const char *pathname, char *args[]);
tor_network_data *icd_tor_find_first_network_data(network_tor_private *
						  private);
tor_network_data *icd_tor_find_network_data(const gchar * network_type,
					    guint network_attrs,
					    const gchar * network_id,
					    network_tor_private * private);
gboolean string_equal(const char *a, const char *b);
int startup_tor(tor_network_data * network_data, char *config);

#define EVENT_SOURCE_IP_UP 1
#define EVENT_SOURCE_IP_DOWN 2
#define EVENT_SOURCE_GCONF_CHANGE 3
#define EVENT_SOURCE_TOR_PID_EXIT 4
#define EVENT_SOURCE_TOR_BOOTSTRAPPED_PID_EXIT 5
/* TODO: extend with dbus */

#endif
