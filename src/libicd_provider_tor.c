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

#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <pwd.h>
#include <signal.h>

#include <glib.h>
#include <gconf/gconf-client.h>

#include <osso-ic-gconf.h>
#include <support/icd_log.h>
#include <support/icd_dbus.h>

#include <srv_provider_api.h>

#include "libicd_tor.h"

#define TP_DEBUG(fmt, ...) ILOG_DEBUG(("[TOR PROVIDER] "fmt), ##__VA_ARGS__)
#define TP_INFO(fmt, ...) ILOG_INFO(("[TOR PROVIDER] " fmt), ##__VA_ARGS__)
#define TP_WARN(fmt, ...) ILOG_WARN(("[TOR PROVIDER] %s.%d:" fmt), __func__, __LINE__, ##__VA_ARGS__)
#define TP_ERR(fmt, ...) ILOG_ERR(("[TOR PROVIDER] %s.%d:" fmt), __func__, __LINE__, ##__VA_ARGS__)
#define TP_CRIT(fmt, ...) ILOG_CRIT(("[TOR PROVIDER] %s.%d:" fmt), __func__, __LINE__, ##__VA_ARGS__)

struct _provider_tor_private {
	/* For pid monitoring */
	icd_srv_watch_pid_fn watch_cb;
	gpointer watch_cb_token;

	icd_srv_close_fn close_fn;
	icd_srv_limited_conn_fn limited_conn_fn;

	GSList *network_data_list;
};
typedef struct _provider_tor_private provider_tor_private;

#define PROVIDER_TOR_STATE_NONE 0
#define PROVIDER_TOR_STATE_STOPPED 1
#define PROVIDER_TOR_STATE_STARTED 2
#define PROVIDER_TOR_STATE_CONNECTED 3

struct _tor_network_data {
	provider_tor_private *private;

	int state;

	icd_srv_connect_cb_fn connect_cb;
	gpointer connect_cb_token;

	/* For matching / callbacks later on (like close and limited_conn callback) */
	gchar *service_type;
	guint service_attrs;
	gchar *service_id;
	gchar *network_type;
	guint network_attrs;
	gchar *network_id;
};
typedef struct _tor_network_data tor_network_data;

gboolean icd_srv_init(struct icd_srv_api *srv_api,
		      icd_srv_watch_pid_fn watch_cb,
		      gpointer watch_cb_token, icd_srv_close_fn close, icd_srv_limited_conn_fn limited_conn);

/* XXX: Taken from ipv4 module */
static gboolean string_equal(const char *a, const char *b)
{
	if (!a)
		return !b;

	if (b)
		return !strcmp(a, b);

	return FALSE;
}

static tor_network_data *icd_tor_find_first_network_data(provider_tor_private * private)
{
	GSList *l;

	for (l = private->network_data_list; l; l = l->next) {
		tor_network_data *found = (tor_network_data *) l->data;

		if (!found)
			TP_WARN("tor network data is NULL");
		else {
			return found;
		}
	}

	return NULL;
}

static tor_network_data *icd_tor_find_network_data(const gchar * network_type, guint network_attrs,
						   const gchar * network_id, provider_tor_private * private)
{
	GSList *l;

	for (l = private->network_data_list; l; l = l->next) {
		tor_network_data *found = (tor_network_data *) l->data;

		if (!found)
			TP_WARN("tor network data is NULL");
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

static void tor_get_stop_reply(DBusPendingCall * pending, gpointer user_data)
{
	/* We don't care */
	return;
}

static void network_free_all(tor_network_data * network_data)
{
	provider_tor_private *priv = network_data->private;
	if (priv->network_data_list) {
		priv->network_data_list = g_slist_remove(priv->network_data_list, network_data);
	}

	g_free(network_data->service_type);
	g_free(network_data->service_id);
	g_free(network_data->network_type);
	g_free(network_data->network_id);

	network_data->private = NULL;

	g_free(network_data);
}

static void network_stop_all(tor_network_data * network_data)
{
	DBusMessage *msg;
	msg = dbus_message_new_method_call(ICD_TOR_DBUS_INTERFACE, ICD_TOR_DBUS_PATH, ICD_TOR_DBUS_INTERFACE, "Stop");

	if (icd_dbus_send_system_mcall(msg, -1, tor_get_stop_reply, network_data) == FALSE) {
		/* Call down callback right away */
		TP_WARN("icd_dbus_send_system_msg failed when requesting Stop");
		dbus_message_unref(msg);

		return;
	}

	dbus_message_unref(msg);
}

static void tor_get_start_reply(DBusPendingCall * pending, gpointer user_data)
{
	DBusMessage *message;
	int reply = 0;
	tor_network_data *network_data = user_data;

	message = dbus_pending_call_steal_reply(pending);

	if (message && dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_METHOD_RETURN) {
		dbus_message_get_args(message, NULL, DBUS_TYPE_INT32, &reply, DBUS_TYPE_INVALID);
	}

	if (reply != TOR_DBUS_METHOD_START_RESULT_OK) {
		network_data->connect_cb(ICD_SRV_ERROR, NULL, network_data->connect_cb_token);
		network_free_all(network_data);
	}

	/* Otherwise, we wait for status changed signal(s) - assuming we don't get
	 * them before the method reply (yikes) */
	return;
}

static DBusHandlerResult
tor_provider_statuschanged_sig(DBusConnection * connection, DBusMessage * message, void *user_data)
{
	provider_tor_private *priv = user_data;

	if (dbus_message_is_signal(message, ICD_TOR_DBUS_INTERFACE, ICD_TOR_SIGNAL_STATUSCHANGED)) {
		const char *status = NULL;
		const char *mode = NULL;
		int new_state = PROVIDER_TOR_STATE_NONE;

		if (!dbus_message_get_args(message, NULL,
					   DBUS_TYPE_STRING, &status, DBUS_TYPE_STRING, &mode, DBUS_TYPE_INVALID)) {
			TP_WARN("Unable to parse arguments of " ICD_TOR_SIGNAL_STATUSCHANGED);
		}

		/* Find network data, check status, potentially call callbacks based on
		 * state */
		tor_network_data *network_data = icd_tor_find_first_network_data(priv);

		if (network_data == NULL) {
			/* We're likely just not active at all */
			goto done;
		}

		if (strcmp(status, ICD_TOR_SIGNALS_STATUS_STATE_STOPPED) == 0) {
			TP_DEBUG("New state: Stopped");
			new_state = PROVIDER_TOR_STATE_STOPPED;
		} else if (strcmp(status, ICD_TOR_SIGNALS_STATUS_STATE_STARTED) == 0) {
			TP_DEBUG("New state: Started");
			new_state = PROVIDER_TOR_STATE_STARTED;
		} else if (strcmp(status, ICD_TOR_SIGNALS_STATUS_STATE_CONNECTED) == 0) {
			TP_DEBUG("New state: Connected");
			new_state = PROVIDER_TOR_STATE_CONNECTED;
		}

		/* We could get an unexpected stop, or the expected start (after we
		 * start it */
		if (network_data->state > new_state) {
			/* Tor quit, let's throw down the interface */

			priv->close_fn(ICD_SRV_ERROR, "Tor process quit (unexpectedly)",
				       network_data->service_type,
				       network_data->service_attrs,
				       network_data->service_id,
				       network_data->network_type,
				       network_data->network_attrs, network_data->network_id);
			goto done;
		}

		if (new_state > network_data->state) {
			if (new_state == PROVIDER_TOR_STATE_CONNECTED) {
				network_data->connect_cb(ICD_SRV_SUCCESS, NULL, network_data->connect_cb_token);
			}
		}

		if (new_state == network_data->state) {
			/* Nothing changed. */
		}

		network_data->state = new_state;
	}

 done:
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

/**
 * Function to connect (or authenticate) to the service provider.
 *
 * @param service_type      service type
 * @param service_attrs     service attributes
 * @param service_id        internal id identifying the service
 * @param network_type      type of network connected to
 * @param network_attrs     network attributes
 * @param network_id        network identification
 * @param interface_name    network interface used
 * @param connect_cb        callback to call when connection attempt is
 *                          completed
 * @param connect_cb_token  token to pass to the callback
 * @param private           reference to the private icd_srv_api member
 */
static void tor_connect(const gchar * service_type,
			const guint service_attrs,
			const gchar * service_id,
			const gchar * network_type,
			const guint network_attrs,
			const gchar * network_id,
			const gchar * interface_name,
			icd_srv_connect_cb_fn connect_cb, gpointer connect_cb_token, gpointer * private)
{
	provider_tor_private *priv = *private;
	TP_DEBUG("tor_connect: %s\n", network_id);

	tor_network_data *network_data = g_new0(tor_network_data, 1);

	network_data->service_type = g_strdup(service_type);
	network_data->service_id = g_strdup(service_id);
	network_data->service_attrs = service_attrs;
	network_data->network_type = g_strdup(network_type);
	network_data->network_attrs = network_attrs;
	network_data->network_id = g_strdup(network_id);

	network_data->connect_cb = connect_cb;
	network_data->connect_cb_token = connect_cb_token;
	network_data->private = priv;

	network_data->state = PROVIDER_TOR_STATE_STOPPED;

	/* Issue dbus call, and upon dbus call result, call the connect_cb */

	DBusMessage *msg;
	msg = dbus_message_new_method_call(ICD_TOR_DBUS_INTERFACE, ICD_TOR_DBUS_PATH, ICD_TOR_DBUS_INTERFACE, "Start");
	dbus_message_append_args(msg, DBUS_TYPE_STRING, &service_id, DBUS_TYPE_INVALID);

	if (icd_dbus_send_system_mcall(msg, -1, tor_get_start_reply, network_data) == FALSE) {
		/* Call down callback right away */
		TP_WARN("icd_dbus_send_system_msg failed when requesting Start");
		dbus_message_unref(msg);

		connect_cb(ICD_SRV_ERROR, NULL, connect_cb_token);

		return;
	}

	dbus_message_unref(msg);

	priv->network_data_list = g_slist_prepend(priv->network_data_list, network_data);
	return;
}

/**
 * Function to disconnect the service provider
 *
 * @param service_type         service type
 * @param service_attrs        service attributes
 * @param service_id           internal id identifying the service
 * @param network_type         type of network connected to
 * @param network_attrs        network attributes
 * @param network_id           network identification
 * @param interface_name       network interface used
 * @param disconnect_cb        callback to call when disconnection is
 *                             completed
 * @param disconnect_cb_token  token to pass to the callback
 * @param private              reference to the private icd_srv_api member
 */
static void tor_disconnect(const gchar * service_type,
			   const guint service_attrs,
			   const gchar * service_id,
			   const gchar * network_type,
			   const guint network_attrs,
			   const gchar * network_id,
			   const gchar * interface_name,
			   icd_srv_disconnect_cb_fn disconnect_cb, gpointer disconnect_cb_token, gpointer * private)
{
	TP_DEBUG("tor_disconnect: %s\n", network_id);
	provider_tor_private *priv = *private;

	tor_network_data *network_data = icd_tor_find_network_data(network_type, network_attrs, network_id, priv);

	if (network_data) {
		network_stop_all(network_data);
		network_free_all(network_data);
	}

	disconnect_cb(ICD_SRV_SUCCESS, disconnect_cb_token);
	return;
}

/* Dummy service provider function to identify if a scan result is usable by the
 * provider.
 *
 * @param status             status, see #icd_scan_status
 * @param network_type       network type
 * @param network_name       name of the network displayable to the user
 * @param network_attrs      network attributes
 * @param network_id         network identification
 * @param signal             signal strength
 * @param station_id         station id, e.g. MAC address or similar id
 * @param dB                 absolute signal strength value in dB
 * @param identify_cb        callback to call when the identification has
 *                           been done
 * @param identify_cb_token  token to pass to the identification callback
 */
static void tor_identify(enum icd_scan_status status,
			 const gchar * network_type,
			 const gchar * network_name,
			 const guint network_attrs,
			 const gchar * network_id,
			 const guint network_priority,
			 enum icd_nw_levels signal,
			 const gchar * station_id,
			 const gint dB,
			 icd_srv_identify_cb_fn identify_cb, gpointer identify_cb_token, gpointer * private)
{
	TP_DEBUG("tor_identify: network_type: %s, network_name: %s, network_id: %s\n", network_type, network_name,
		 network_id);

	char *gconf_service_id = NULL;
	gboolean match = FALSE;

	match = network_is_tor_provider(network_id, &gconf_service_id);

	/* We construct a name here to make it apparent this is a tor provider */
	gchar *name = g_strconcat(network_name, " (", TOR_PROVIDER_NAME, ") ", NULL);
	TP_DEBUG("tor_identify: called for: %s\n", name);

	if (match) {
		identify_cb(ICD_SRV_IDENTIFIED, TOR_PROVIDER_TYPE,	/* service type */
			    name,
			    TOR_DEFAULT_SERVICE_ATTRIBUTES,
			    gconf_service_id,
			    TOR_DEFAULT_SERVICE_PRIORITY, network_type, network_attrs, network_id, identify_cb_token);

	} else {
		/* XXX: Do we really need to add provider type and provider id when we
		 * don't match it? */
		identify_cb(ICD_SRV_UNKNOWN, TOR_PROVIDER_TYPE,	/* service type */
			    name,
			    TOR_DEFAULT_SERVICE_ATTRIBUTES,
			    gconf_service_id,
			    TOR_DEFAULT_SERVICE_PRIORITY, network_type, network_attrs, network_id, identify_cb_token);
	}

	g_free(gconf_service_id);
	g_free(name);
	return;
}

/**
 * Function to handle service provider destruction
 *
 * @param private  a reference to the icd_nw_api private member
 */
static void tor_srv_destruct(gpointer * private)
{
	provider_tor_private *priv = *private;

	TP_DEBUG("tor_srv_destruct: priv %p\n", priv);

	tor_network_data *data = NULL;
	while (data = icd_tor_find_first_network_data(priv), data != NULL) {
		network_free_all(data);
	}

	g_free(priv);
	return;
}

/** Dummy service provider module initialization function.
 * @param srv_api icd_srv_api structure filled in by the module
 * @param watch_cb function to inform ICd that a child process is to be
 *        monitored for exit status
 * @param watch_cb_token token to pass to the watch pid function
 * @param close_cb function to inform ICd that the network connection is to be
 *        closed
 * @param limited_conn function to inform about limited connectivity for service
 *        providing purposes. (optional)
 * @return TRUE on succes; FALSE on failure whereby the module is unloaded
 */
gboolean icd_srv_init(struct icd_srv_api * srv_api,
		      icd_srv_watch_pid_fn watch_cb,
		      gpointer watch_cb_token, icd_srv_close_fn close, icd_srv_limited_conn_fn limited_conn)
{
	provider_tor_private *priv = g_new0(provider_tor_private, 1);
	TP_DEBUG("icd_srv_init\n");
	srv_api->version = ICD_SRV_MODULE_VERSION;
	srv_api->private = priv;
	srv_api->connect = tor_connect;
	srv_api->disconnect = tor_disconnect;
	srv_api->identify = tor_identify;
	srv_api->srv_destruct = tor_srv_destruct;
	priv->watch_cb = watch_cb;
	priv->watch_cb_token = watch_cb_token;
	priv->close_fn = close;
	priv->limited_conn_fn = limited_conn;

	if (!icd_dbus_connect_system_bcast_signal
	    (ICD_TOR_DBUS_INTERFACE, tor_provider_statuschanged_sig, priv, ICD_TOR_SIGNAL_STATUSCHANGED_FILTER)) {
		TP_ERR("Unable to listen to icd2 tor signals");
		g_free(priv);
		return FALSE;
	}

	return TRUE;
}
