/*
 * This file is part of libicd-network-tor
 *
 * Copyright (C) 2021, Merlijn Wajer <merlijn@wizzup.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 */

#include <string.h>
#include <glib.h>
#include <gconf/gconf-client.h>

#include <osso-ic-gconf.h>
#include "icd/support/icd_log.h"
#include <network_api.h>

#include "dbus_tor.h"

gboolean icd_nw_init(struct icd_nw_api *network_api,
		     icd_nw_watch_pid_fn watch_cb,
		     gpointer watch_cb_token, icd_nw_close_fn close_cb);

/** Function for configuring an IP address.
 * @param network_type network type
 * @param network_attrs attributes, such as type of network_id, security, etc.
 * @param network_id IAP name or local id, e.g. SSID
 * @param interface_name interface that was enabled
 * @param link_up_cb callback function for notifying ICd when the IP address
 *        is configured
 * @param link_up_cb_token token to pass to the callback function
 * @param private a reference to the icd_nw_api private memeber
 */
static void tor_ip_up(const gchar * network_type,
		      const guint network_attrs,
		      const gchar * network_id,
		      const gchar * interface_name,
		      icd_nw_ip_up_cb_fn ip_up_cb,
		      gpointer ip_up_cb_token, gpointer * private)
{
	ILOG_DEBUG("TOR LINK UP");

	/* TODO: can we just pass NULL instead of env_set ? */
	const gchar *env_set[] = {
		NULL
	};

	// TODO: do we want ICD_NW_SUCCESS or ICD_NW_SUCCESS_NEXT_LAYER?
	ip_up_cb(ICD_NW_SUCCESS_NEXT_LAYER,
		 NULL, ip_up_cb_token, env_set, NULL);
}

/**
 * Function for deconfiguring the IP layer, e.g. relasing the IP address.
 * Normally this function need not to be provided as the libicd_network_ipv4
 * network module provides IP address deconfiguration in a generic fashion.
 *
 * @param network_type      network type
 * @param network_attrs     attributes, such as type of network_id, security,
 *                          etc.
 * @param network_id        IAP name or local id, e.g. SSID
 * @param interface_name    interface name
 * @param ip_down_cb        callback function for notifying ICd when the IP
 *                          address is deconfigured
 * @param ip_down_cb_token  token to pass to the callback function
 * @param private           a reference to the icd_nw_api private member
 */
static void
tor_ip_down(const gchar * network_type, guint network_attrs,
	    const gchar * network_id, const gchar * interface_name,
	    icd_nw_ip_down_cb_fn ip_down_cb, gpointer ip_down_cb_token,
	    gpointer * private)
{
	ILOG_DEBUG("TOR LINK DOWN");
	ip_down_cb(ICD_NW_SUCCESS, ip_down_cb_token);
}

static void tor_network_destruct(gpointer * private)
{
	free_tor_dbus();
#if 0
	ipv4_private *priv = *private;

	if (priv->network_data_list)
		ILOG_CRIT("ipv4 still has connected networks");

	icd_dbus_disconnect_system_bcast_signal(ICD_DBUS_AUTOCONF_INTERFACE,
						icd_ipv4_autoconf_cb, priv,
						"member='"
						ICD_AUTOCONF_CHANGED_SIG "'");
	g_free(priv);
	*private = NULL;
#endif
}

/** Tor network module initialization function.
 * @param network_api icd_nw_api structure filled in by the module
 * @param watch_cb function to inform ICd that a child process is to be
 *        monitored for exit status
 * @param watch_cb_token token to pass to the watch pid function
 * @param close_cb function to inform ICd that the network connection is to be
 *        closed
 * @return TRUE on succes; FALSE on failure whereby the module is unloaded
 */
gboolean icd_nw_init(struct icd_nw_api *network_api,
		     icd_nw_watch_pid_fn watch_cb,
		     gpointer watch_cb_token, icd_nw_close_fn close_cb)
{
	/* TODO */
	void *user_data = NULL;

	network_api->version = ICD_NW_MODULE_VERSION;
	network_api->ip_up = tor_ip_up;
	network_api->ip_down = tor_ip_down;

	if (setup_tor_dbus(user_data)) {
		ILOG_ERR("Could not request dbus interface");
		return FALSE;
	}
	//network_api->child_exit = ...;
	network_api->network_destruct = tor_network_destruct;
	//network_api->private = priv;
#if 0
	priv->watch_fn = watch_fn;
	priv->watch_fn_token = watch_fn_token;
	priv->close_fn = close_fn;
	priv->status_change_fn = status_change_fn;
#endif

	return TRUE;
}
