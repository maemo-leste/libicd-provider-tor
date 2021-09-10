/*
 * This file is part of libicd-tor
 *
 * Copyright (C) 2021, Merlijn Wajer <merlijn@wizzup.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 3.0 as published by the Free Software Foundation.
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

#include "libicd_network_tor.h"

/*
 * TODO:
 *
 * Variables:
 *
 * 1. IAP connected or not (or should be connected or not)
 * 2. IAP has service provider or not
 * 3. Value of gconf key (system wide)
 * 4. Information received from dbus (?) - what if someone does manual start or
 *    stop? (We don't want to bring down the network in such a case, unless it
 *    is a provider, but then the provider will do that itself based on the DBus
 *    interface)
 * 5. ...
 *
 * States (maybe have various states):
 *
 * - 
 *
 *
 * TODO: do we disallow dbus calls when we are in certain states? like trying to
 * get the interface up by starting tor? then dbus calls to stop Tor could be
 * weird
 *
 */

static void tor_state_change(network_tor_private * private,
			     tor_network_data * network_data,
			     network_tor_state new_state, int source)
{
	network_tor_state current_state = private->state;

	if (source == EVENT_SOURCE_IP_UP) {
		if (current_state.iap_connected) {
			ILOG_ERR
			    ("ip_up called when we are already connected\n");
			/* Figure out how to handle this */
		}

		/* Add network to network_data */
		private->network_data_list =
		    g_slist_prepend(private->network_data_list, network_data);

		/* Check if we want to start Tor (system wide enabled), or if we just
		 * call the callback right now */
		if (current_state.system_wide_enabled) {
			int start_ret = 0;

			start_ret =
			    startup_tor(network_data, new_state.active_config);

			if (start_ret != 0) {
				icd_nw_ip_up_cb_fn up_cb =
				    network_data->ip_up_cb;
				gpointer up_token =
				    network_data->ip_up_cb_token;

				if (start_ret == 1) {
					network_free_all(network_data);
				} else if (start_ret == 2) {
					network_stop_all(network_data);
					network_free_all(network_data);
				}

				new_state.iap_connected = FALSE;
				up_cb(ICD_NW_ERROR, NULL, up_token);
			} else {
				new_state.tor_running = TRUE;
				new_state.tor_bootstrapped_running = TRUE;
				new_state.tor_bootstrapped = FALSE;
				/* ip_up_cb will be called later in the bootstrap pid exit */
			}
		} else {
			/* System wide is disabled, so let's just call ip_up_cb right away */
			network_data->ip_up_cb(ICD_NW_SUCCESS, NULL,
					       network_data->ip_up_cb_token,
					       NULL);
			/* TODO: do we need to set a specific state here? */
		}

		emit_status_signal(new_state);
	} else if (source == EVENT_SOURCE_IP_DOWN) {
		icd_nw_ip_down_cb_fn down_cb = network_data->ip_down_cb;
		gpointer down_token = network_data->ip_down_cb_token;

		/* Stop Tor etc, free network data */
		network_stop_all(network_data);
		network_free_all(network_data);

		new_state.tor_running = FALSE;
		new_state.tor_bootstrapped_running = FALSE;
		new_state.tor_bootstrapped = FALSE;

		down_cb(ICD_NW_SUCCESS, down_token);

		emit_status_signal(new_state);
	} else if (source == EVENT_SOURCE_GCONF_CHANGE) {
		/* Might not have network_data here */
	} else if (source == EVENT_SOURCE_TOR_PID_EXIT) {
		if (!current_state.tor_running) {
			ILOG_ERR
			    ("Received tor pid exit but we don't think it was running");
			/* Figure out how to handle this */
		} else {
			/* Something killed Tor (but not us, since we never hit this code
			 * path when we kill Tor) */
			network_data->tor_pid = 0;

			/* This will call tor_disconnect, so we don't free/stop here, since
			 * ip_down should be called */
			private->close_cb(ICD_NW_ERROR,
					  "Tor process quit (unexpectedly)",
					  network_data->network_type,
					  network_data->network_attrs,
					  network_data->network_id);

		}

		emit_status_signal(new_state);
	} else if (source == EVENT_SOURCE_TOR_BOOTSTRAPPED_PID_EXIT) {
		network_data->wait_for_tor_pid = 0;

		if (new_state.tor_bootstrapped) {
			new_state.iap_connected = TRUE;

			network_data->ip_up_cb(ICD_NW_SUCCESS, NULL,
					       network_data->ip_up_cb_token,
					       NULL);
		} else {
			icd_nw_ip_up_cb_fn up_cb = network_data->ip_up_cb;
			gpointer up_token = network_data->ip_up_cb_token;

			/* Maybe we should not free here */
			new_state.iap_connected = FALSE;
			network_free_all(network_data);

			up_cb(ICD_NW_ERROR, NULL, up_token);
		}

		emit_status_signal(new_state);
	}

	/* Free old active_config if it is not the same pointer as in new_state */
	if (current_state.active_config != NULL
	    && current_state.active_config != new_state.active_config) {
		free(current_state.active_config);
	}
	// Move to new state
	memcpy(&private->state, &new_state, sizeof(network_tor_state));
}

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
	network_tor_private *priv = *private;
	ILOG_DEBUG("tor_ip_up");

	tor_network_data *network_data = g_new0(tor_network_data, 1);

	network_data->network_type = g_strdup(network_type);
	network_data->network_attrs = network_attrs;
	network_data->network_id = g_strdup(network_id);

	network_data->ip_up_cb = ip_up_cb;
	network_data->ip_up_cb_token = ip_up_cb_token;
	network_data->private = priv;

	network_tor_state new_state;
	memcpy(&new_state, &priv->state, sizeof(network_tor_state));
	new_state.iap_connected = TRUE;
	new_state.active_config = get_active_config();

	tor_state_change(priv, network_data, new_state, EVENT_SOURCE_IP_UP);

	return;
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
	ILOG_DEBUG("tor_ip_down");
	network_tor_private *priv = *private;

	tor_network_data *network_data =
	    icd_tor_find_network_data(network_type, network_attrs, network_id,
				      priv);

	network_data->ip_down_cb = ip_down_cb;
	network_data->ip_down_cb_token = ip_down_cb_token;

	network_tor_state new_state;
	memcpy(&new_state, &priv->state, sizeof(network_tor_state));
	new_state.iap_connected = FALSE;

	tor_state_change(priv, network_data, new_state, EVENT_SOURCE_IP_DOWN);
}

static void tor_network_destruct(gpointer * private)
{
	network_tor_private *priv = *private;

	ILOG_DEBUG("tor_network_destruct");

	if (priv->gconf_client != NULL) {
		if (priv->gconf_cb_id_systemwide != 0) {
			gconf_client_notify_remove(priv->gconf_client,
						   priv->gconf_cb_id_systemwide);
			priv->gconf_cb_id_systemwide = 0;
		}

		g_object_unref(priv->gconf_client);
	}
	free_tor_dbus();

	if (priv->network_data_list)
		ILOG_CRIT("ipv4 still has connected networks");

	g_free(priv);
}

/**
 * Function to handle child process termination
 *
 * @param pid         the process id that exited
 * @param exit_value  process exit value
 * @param private     a reference to the icd_nw_api private member
 */
static void tor_child_exit(const pid_t pid,
			   const gint exit_status, gpointer * private)
{
	/* TODO: add state logic here */
	GSList *l;
	network_tor_private *priv = *private;
	tor_network_data *network_data;

	enum pidtype { UNKNOWN, TOR_PID, WAIT_FOR_TOR_PID };

	int pid_type = UNKNOWN;

	for (l = priv->network_data_list; l; l = l->next) {
		network_data = (tor_network_data *) l->data;
		if (network_data) {
			if (network_data->tor_pid == pid) {
				pid_type = TOR_PID;
				break;
			}
			if (network_data->wait_for_tor_pid == pid) {
				pid_type = WAIT_FOR_TOR_PID;
				break;
			}
			/* Do we want to do anything with unknown pids? */

		} else {
			/* This can happen if we are manually disconnecting, and we already
			   free the network data and kill tor, then we won't have the
			   network_data anymore */
			ILOG_DEBUG
			    ("tor_child_exit: network_data_list contains empty network_data");
		}
	}

	if (!l) {
		ILOG_ERR
		    ("tor_child_exit: got pid %d but did not find network_data\n",
		     pid);
		return;
	}

	if (pid_type == TOR_PID) {
		ILOG_INFO("Tor process stopped");

		network_tor_state new_state;
		memcpy(&new_state, &priv->state, sizeof(network_tor_state));
		new_state.tor_running = FALSE;

		tor_state_change(priv, network_data, new_state,
				 EVENT_SOURCE_TOR_PID_EXIT);
	} else if (pid_type == WAIT_FOR_TOR_PID) {

		ILOG_INFO("Got wait-for-tor pid: %d with status %d", pid,
			  exit_status);

		network_tor_state new_state;
		memcpy(&new_state, &priv->state, sizeof(network_tor_state));
		new_state.tor_bootstrapped_running = FALSE;

		if (exit_status == 0) {
			new_state.tor_bootstrapped = TRUE;
		} else {
			ILOG_WARN("wait-for-tor failed with %d\n", exit_status);
			new_state.tor_bootstrapped = FALSE;
		}

		tor_state_change(priv, network_data, new_state,
				 EVENT_SOURCE_TOR_BOOTSTRAPPED_PID_EXIT);
	}

	return;
}

static void gconf_callback(GConfClient * client, guint cnxn_id,
			   GConfEntry * entry, gpointer user_data)
{
	network_tor_private *priv = user_data;
	gboolean system_wide_enabled = gconf_value_get_bool(entry->value);
	fprintf(stderr, "gconf_callback: system_wide = %d\n",
		system_wide_enabled);

	network_tor_state new_state;
	memcpy(&new_state, &priv->state, sizeof(network_tor_state));
	new_state.system_wide_enabled = system_wide_enabled;
	tor_state_change(priv, NULL, new_state, EVENT_SOURCE_GCONF_CHANGE);
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
		     icd_nw_watch_pid_fn watch_fn, gpointer watch_fn_token,
		     icd_nw_close_fn close_fn,
		     icd_nw_status_change_fn status_change_fn,
		     icd_nw_renew_fn renew_fn)
{
	network_tor_private *priv = g_new0(network_tor_private, 1);

	network_api->version = ICD_NW_MODULE_VERSION;
	network_api->ip_up = tor_ip_up;
	network_api->ip_down = tor_ip_down;

	priv->state.system_wide_enabled = get_system_wide_enabled();
	priv->state.active_config = NULL;
	priv->state.iap_connected = FALSE;
	priv->state.tor_running = FALSE;
	priv->state.tor_bootstrapped_running = FALSE;
	priv->state.tor_bootstrapped = FALSE;

	priv->gconf_client = gconf_client_get_default();
	GError *error = NULL;
	gconf_client_add_dir(priv->gconf_client, GC_NETWORK_TYPE,
			     GCONF_CLIENT_PRELOAD_NONE, &error);
	if (error != NULL) {
		ILOG_ERR("Could not monitor gconf dir for changes");
		g_clear_error(&error);
		goto err;
	}
	priv->gconf_cb_id_systemwide =
	    gconf_client_notify_add(priv->gconf_client, GC_TOR_SYSTEM,
				    gconf_callback, (void *)priv, NULL, &error);
	if (error != NULL) {
		ILOG_ERR("Could not monitor gconf system wide key for changes");
		g_clear_error(&error);
		goto err;
	}

	if (setup_tor_dbus(priv)) {
		ILOG_ERR("Could not request dbus interface");
		goto err;
	}

	network_api->network_destruct = tor_network_destruct;
	network_api->child_exit = tor_child_exit;

	priv->watch_cb = watch_fn;
	priv->watch_cb_token = watch_fn_token;
	priv->close_cb = close_fn;

	network_api->private = priv;

#if 0
	priv->status_change_fn = status_change_fn;
	priv->renew_fn = renew_fn;
#endif

	return TRUE;

 err:
	if (priv->gconf_client) {
		g_object_unref(priv->gconf_client);
		priv->gconf_client = NULL;
	}

	g_free(priv);

	return FALSE;
}
