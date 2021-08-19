/*
 * This file is part of libicd-provider-tor
 *
 * Copyright (C) 2021 Merlijn Wajer <merlijn@wizzup.org>
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

#include <osso-ic-gconf.h>
#include <support/icd_log.h>
#include <srv_provider_api.h>

#define TOR_NETWORK_TYPE "TOR"
#define TOR_PROVIDER_TYPE "TOR"
#define TOR_PROVIDER_NAME "Tor Provider"
#define TOR_PROVIDER_ID "tor-provider"

gboolean icd_srv_init(struct icd_srv_api *srv_api,
		      icd_srv_watch_pid_fn watch_cb,
		      gpointer watch_cb_token,
		      icd_srv_close_fn close,
		      icd_srv_limited_conn_fn limited_conn);

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
			  icd_srv_connect_cb_fn connect_cb,
			  gpointer connect_cb_token, gpointer * private)
{
	ILOG_DEBUG("tor_connect: %s\n", network_id);
	connect_cb(ICD_SRV_SUCCESS, NULL, connect_cb_token);
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
			     icd_srv_disconnect_cb_fn disconnect_cb,
			     gpointer disconnect_cb_token, gpointer * private)
{
	ILOG_DEBUG("tor_disconnect: %s\n", network_id);
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
			   icd_srv_identify_cb_fn identify_cb,
			   gpointer identify_cb_token, gpointer * private)
{
	ILOG_DEBUG
	    ("tor_identify: network_type: %s, network_name: %s, network_id: %s\n",
	     network_type, network_name, network_id);

	GConfClient *gconf_client;
	GConfValue *value;
	GError *error = NULL;
	gchar *iap_gconf_key;
	const char *gconf_service_type = NULL;

	gconf_client = gconf_client_get_default();

	// TODO: we don't read service_id yet
	// TODO: check this code for memleaks
	iap_gconf_key =
	    g_strdup_printf("/system/osso/connectivity/IAP/%s/service_type",
			    network_id);
	value = gconf_client_get(gconf_client, iap_gconf_key, &error);
	g_free(iap_gconf_key);

	if (error) {
		g_clear_error(&error);
	} else {
		gconf_service_type = gconf_value_get_string(value);
	}

	g_object_unref(gconf_client);

	/* We construct a name here to make it apparent this is a tor provider */
	gchar *name =
	    g_strconcat(network_name, " (", TOR_PROVIDER_NAME, ") ", NULL);
	ILOG_DEBUG("tor_identify: called for: %s\n", name);

	if (g_strcmp0(TOR_PROVIDER_NAME, gconf_service_type) == 0) {
		ILOG_DEBUG("tor_identify: MATCH\n");
		identify_cb(ICD_SRV_IDENTIFIED, TOR_PROVIDER_TYPE,	/* service type */
			    name, 0,	/* XXX: service attributes */
			    TOR_PROVIDER_ID, 0,	/* XXX: service priority */
			    network_type,
			    network_attrs, network_id, identify_cb_token);

	} else {
		ILOG_DEBUG("tor_identify: NO MATCH\n");
		identify_cb(ICD_SRV_UNKNOWN, TOR_PROVIDER_TYPE,	/* service type */
			    name, 0,	/* XXX: service attributes */
			    TOR_PROVIDER_ID, 0,	/* XXX: service priority */
			    network_type,
			    network_attrs, network_id, identify_cb_token);
	}

	free(name);
	return;
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
	ILOG_DEBUG("tor_child_exit\n");
	return;
}

/**
 * Function to handle service provider destruction
 *
 * @param private  a reference to the icd_nw_api private member
 */
static void tor_srv_destruct(gpointer * private)
{
	ILOG_DEBUG("tor_srv_destruct\n");
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
		      gpointer watch_cb_token,
		      icd_srv_close_fn close,
		      icd_srv_limited_conn_fn limited_conn)
{
	ILOG_DEBUG("icd_srv_init\n");

	srv_api->version = ICD_SRV_MODULE_VERSION;
	srv_api->private = NULL;
	srv_api->connect = tor_connect;
	srv_api->disconnect = tor_disconnect;
	srv_api->identify = tor_identify;
	srv_api->child_exit = tor_child_exit;
	srv_api->srv_destruct = tor_srv_destruct;

	return TRUE;
}
