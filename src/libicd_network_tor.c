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
#include <stdio.h>
#include <glib.h>
#include <gconf/gconf-client.h>
#include <pwd.h>

#include <osso-ic-gconf.h>
#include "icd/support/icd_log.h"
#include <network_api.h>

#include "dbus_tor.h"
#include "libicd_tor.h"

struct _network_tor_private {
	/* For pid monitoring */
	icd_nw_watch_pid_fn watch_cb;
	gpointer watch_cb_token;

	icd_nw_close_fn close_cb;

#if 0
	icd_srv_limited_conn_fn limited_conn_fn;
#endif

	GSList *network_data_list;
};
typedef struct _network_tor_private network_tor_private;

struct _tor_network_data {
	network_tor_private *private;

	icd_nw_ip_up_cb_fn ip_up_cb;
	gpointer ip_up_cb_token;

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

/* XXX: Taken from ipv4 module */
static gboolean string_equal(const char *a, const char *b)
{
	if (!a)
		return !b;

	if (b)
		return !strcmp(a, b);

	return FALSE;
}

static tor_network_data *icd_tor_find_network_data(const gchar * network_type,
						   guint network_attrs,
						   const gchar * network_id,
						   network_tor_private *
						   private)
{
	GSList *l;

	for (l = private->network_data_list; l; l = l->next) {
		tor_network_data *found = (tor_network_data *) l->data;

		if (!found)
			ILOG_WARN("tor network data is NULL");
		else {
			if (found->network_attrs == network_attrs &&
			    string_equal(found->network_type, network_type) &&
			    string_equal(found->network_id, network_id)) {
				return found;
			}
		}
	}

	return NULL;
}

/* pathname and arg are like in execv, returns pid, 0 is error */
static pid_t spawn_as(const char *username, const char *pathname, char *args[])
{
	struct passwd *ent = getpwnam(username);
	if (ent == NULL) {
		ILOG_CRIT("spawn_tor: getpwnam failed\n");
		return 0;
	}

	pid_t pid = fork();
	if (pid < 0) {
		ILOG_CRIT("spawn_tor: fork() failed\n");
		return 0;
	} else if (pid == 0) {
		if (setgid(ent->pw_gid)) {
			ILOG_CRIT("setgid failed\n");
			exit(1);
		}
		if (setuid(ent->pw_uid)) {
			ILOG_CRIT("setuid failed\n");
			exit(1);
		}
		execv(pathname, args);

		ILOG_CRIT("execv failed\n");
		exit(1);
	} else {
		ILOG_DEBUG("spawn_as got pid: %d\n", pid);
		return pid;
	}

	return 0;		// Failure
}

static void network_free_all(tor_network_data * network_data)
{
	network_tor_private *priv = network_data->private;
	if (priv->network_data_list) {
		priv->network_data_list =
		    g_slist_remove(priv->network_data_list, network_data);
	}

	g_free(network_data->network_type);
	g_free(network_data->network_id);

	network_data->private = NULL;

	g_free(network_data);
}

static void network_stop_all(tor_network_data * network_data)
{
	if (network_data->tor_pid != 0) {
		kill(network_data->tor_pid, SIGTERM);
		network_data->tor_pid = 0;
	}
	if (network_data->wait_for_tor_pid != 0) {
		kill(network_data->wait_for_tor_pid, SIGTERM);
		network_data->wait_for_tor_pid = 0;
	}
}

gboolean icd_nw_init(struct icd_nw_api *network_api,
		     icd_nw_watch_pid_fn watch_fn, gpointer watch_fn_token,
		     icd_nw_close_fn close_fn,
		     icd_nw_status_change_fn status_change_fn,
		     icd_nw_renew_fn renew_fn);

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

	/* TODO: read gconf, and maybe do nothing based on gconf */

	char *active_config = get_active_config();

	char config_filename[256];
	if (snprintf
	    (config_filename, 256, "/etc/tor/torrc-network-%s",
	     active_config) >= 256) {
		ILOG_WARN("Unable to allocate torrc config filename\n");
		ip_up_cb(ICD_NW_ERROR, NULL, ip_up_cb_token);
		network_stop_all(network_data);
		network_free_all(network_data);
		return;
	}

	char *config_content = generate_config(active_config);
	GError *error = NULL;
	g_file_set_contents(config_filename, config_content,
			    strlen(config_content), &error);
	if (error != NULL) {
		g_clear_error(&error);
		ILOG_WARN("Unable to write Tor config file\n");
		ip_up_cb(ICD_NW_ERROR, NULL, ip_up_cb_token);
		network_stop_all(network_data);
		network_free_all(network_data);
		return;
	}

	char *argss[] = { "/usr/bin/tor", "-f", config_filename, NULL };
	pid_t pid = spawn_as("debian-tor", "/usr/bin/tor", argss);
	if (pid == 0) {
		ILOG_WARN("Failed to start Tor\n");
		ip_up_cb(ICD_NW_ERROR, NULL, ip_up_cb_token);
		network_stop_all(network_data);
		return;
	}

	network_data->tor_pid = pid;
	network_data->private->watch_cb(pid,
					network_data->private->watch_cb_token);

	gchar *gc_controlport =
	    g_strjoin("/", GC_TOR, active_config, GC_CONTROLPORT, NULL);
	GConfClient *gconf = gconf_client_get_default();
	gint control_port = gconf_client_get_int(gconf, gc_controlport, NULL);
	g_object_unref(gconf);
	g_free(gc_controlport);
	char cport[64];
	snprintf(cport, 64, "%d", control_port);

	char *argsv[] =
	    { "/usr/bin/libicd-tor-wait-bootstrapped", cport, NULL };

	pid =
	    spawn_as("debian-tor", "/usr/bin/libicd-tor-wait-bootstrapped",
		     argsv);
	if (pid == 0) {
		ILOG_WARN("Failed to start wait for bootstrapping script\n");
		ip_up_cb(ICD_NW_ERROR, NULL, ip_up_cb_token);
		network_stop_all(network_data);
		return;
	}
	network_data->wait_for_tor_pid = pid;
	network_data->private->watch_cb(pid,
					network_data->private->watch_cb_token);

	/* Add it once we have both pids */
	priv->network_data_list =
	    g_slist_prepend(priv->network_data_list, network_data);

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

	if (network_data) {
		network_stop_all(network_data);
		network_free_all(network_data);
	}

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
		/* If we get here, we probably did not kill Tor ourselves, since we
		 * typically remove the network_data right after that, so we will also
		 * (always) issue priv->close_fn here */
		network_data->tor_pid = 0;

		ILOG_DEBUG("tor_child_exit for pid: %d\n", pid);
		ILOG_INFO("Tor process stopped");

		/* This will call tor_disconnect, so we don't free/stop here */
		priv->close_cb(ICD_NW_ERROR, "Tor process quit (unexpectedly)",
			       network_data->network_type,
			       network_data->network_attrs,
			       network_data->network_id);
	} else if (pid_type == WAIT_FOR_TOR_PID) {
		network_data->wait_for_tor_pid = 0;
		ILOG_INFO("Got wait-for-tor pid: %d with status %d", pid,
			  exit_status);

		if (exit_status == 0) {
			network_data->ip_up_cb(ICD_NW_SUCCESS, NULL,
					       network_data->ip_up_cb_token,
					       NULL);
		} else {
			ILOG_WARN("wait-for-tor failed with %d\n", exit_status);
			network_data->ip_up_cb(ICD_NW_ERROR, NULL,
					       network_data->ip_up_cb_token);
			/* This will make icd2 issue disconnect, so we don't free/stop here */
		}
	}

	return;
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
gboolean icd_nw_init(struct icd_nw_api * network_api,
		     icd_nw_watch_pid_fn watch_fn, gpointer watch_fn_token,
		     icd_nw_close_fn close_fn,
		     icd_nw_status_change_fn status_change_fn,
		     icd_nw_renew_fn renew_fn)
{
	network_tor_private *priv = g_new0(network_tor_private, 1);

	network_api->version = ICD_NW_MODULE_VERSION;
	network_api->ip_up = tor_ip_up;
	network_api->ip_down = tor_ip_down;

	if (setup_tor_dbus(priv)) {
		ILOG_ERR("Could not request dbus interface");
		return FALSE;
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
}
