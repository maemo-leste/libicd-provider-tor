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
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <pwd.h>
#include <signal.h>

#include <glib.h>
#include <gconf/gconf-client.h>

#include <osso-ic-gconf.h>
#include <support/icd_log.h>
#include <srv_provider_api.h>

#define TOR_NETWORK_TYPE "TOR"
#define TOR_PROVIDER_TYPE "TOR"
#define TOR_PROVIDER_NAME "Tor Provider"
#define TOR_PROVIDER_ID "tor-provider"


struct _provider_tor_private {
    /* For pid monitoring */
    icd_srv_watch_pid_fn watch_cb;
    gpointer watch_cb_token;

    icd_srv_close_fn close_fn;
    icd_srv_limited_conn_fn limited_conn_fn;

    GSList *network_data_list;

    /* Maybe: */
    /* pw_uid and pw_gid for debian-tor */

};
typedef struct _provider_tor_private provider_tor_private;

struct _tor_network_data {
    provider_tor_private* private;

    icd_srv_connect_cb_fn connect_cb;
    gpointer connect_cb_token;

    /* Tor pid */
    pid_t tor_pid;

    /* Tor command auth pw/token */
    char* tor_stem_auth;

    /* "Wait for Tor" stem script */
    pid_t wait_for_tor_pid;

    /* For matching / callbacks later on (like close and limited_conn callback) */
    gchar* service_type;
    guint service_attrs;
    gchar *service_id;
    gchar *network_type;
    guint network_attrs;
    gchar *network_id;
};
typedef struct _tor_network_data tor_network_data;

gboolean icd_srv_init(struct icd_srv_api *srv_api,
		      icd_srv_watch_pid_fn watch_cb,
		      gpointer watch_cb_token,
		      icd_srv_close_fn close,
		      icd_srv_limited_conn_fn limited_conn);


/* XXX: Taken from ipv4 module */
static gboolean
string_equal(const char *a, const char *b)
{
  if (!a)
    return !b;

  if (b)
    return !strcmp(a, b);

  return FALSE;
}

/* TODO: maybe also check for service_type, service_id, service_attrs */
static tor_network_data *
icd_tor_find_network_data(const gchar *network_type, guint network_attrs,
                           const gchar *network_id, provider_tor_private *private)
{
  GSList *l;

  for (l = private->network_data_list; l; l = l->next)
  {
    tor_network_data *found = (tor_network_data *)l->data;

    if (!found)
      ILOG_WARN("tor network data is NULL");
    else
    {
      if (found->network_attrs == network_attrs &&
          string_equal(found->network_type, network_type) &&
          string_equal(found->network_id, network_id))
      {
        return found;
      }
    }
  }

  return NULL;
}

/* pathname and arg are like in execl, returns pid, 0 is error */
static pid_t spawn_as(const char* username,
                    const char* pathname, const char *arg, ...) {
    struct passwd * ent = getpwnam(username);
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
        execl(pathname, arg, NULL);
        ILOG_CRIT("execl failed\n");
        exit(1);
    } else {
        ILOG_DEBUG("spawn_as got pid: %d\n", pid);
        return pid;
    }

    return 0; // Failure
}


static void network_free_all(tor_network_data* network_data) {
    provider_tor_private* priv = network_data->private;
    priv->network_data_list = g_slist_remove(priv->network_data_list,
                                             network_data);

    g_free(network_data->service_type);
    g_free(network_data->service_id);
    g_free(network_data->network_type);
    g_free(network_data->network_id);

    network_data->private = NULL;

    g_free(network_data);
}


static void network_stop_all(tor_network_data* network_data) {
    if (network_data->tor_pid != 0) {
        kill(network_data->tor_pid, SIGTERM);
        network_data->tor_pid = 0;
    }
    if (network_data->wait_for_tor_pid != 0) {
        kill(network_data->wait_for_tor_pid, SIGTERM);
        network_data->wait_for_tor_pid = 0;
    }
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
			  icd_srv_connect_cb_fn connect_cb,
			  gpointer connect_cb_token, gpointer * private)
{
    provider_tor_private* priv = *private;
	ILOG_DEBUG("tor_connect: %s\n", network_id);

    tor_network_data* network_data = g_new0(tor_network_data, 1);

    network_data->service_type = g_strdup(service_type);
    network_data->service_id = g_strdup(service_id);
    network_data->service_attrs = service_attrs;
    network_data->network_type = g_strdup(network_type);
    network_data->network_attrs = network_attrs;
    network_data->network_id = g_strdup(network_id);

    network_data->connect_cb = connect_cb;
    network_data->connect_cb_token = connect_cb_token;
    network_data->private = priv;

    pid_t pid = spawn_as("debian-tor", "/usr/bin/tor", "/usr/bin/tor", NULL);
    if (pid == 0) {
        ILOG_WARN("Failed to start Tor\n");
        connect_cb(ICD_SRV_ERROR, NULL, connect_cb_token);
        network_stop_all(network_data);
        network_free_all(network_data);
        return;
    }

    network_data->tor_pid = pid;
    network_data->private->watch_cb(pid, network_data->private->watch_cb_token);

    pid = spawn_as("debian-tor", "/home/user/icd/libicd-provider-tor/wait-bootstrapped.py", "/home/user/icd/libicd-provider-tor/wait-bootstrapped.py");
    if (pid == 0) {
        ILOG_WARN("Failed to start wait for bootstrapping script\n");
        connect_cb(ICD_SRV_ERROR, NULL, connect_cb_token);
        network_stop_all(network_data);
        network_free_all(network_data);
        return;
    }
    network_data->wait_for_tor_pid = pid;
    network_data->private->watch_cb(pid, network_data->private->watch_cb_token);

    /* Add it once we have both pids */
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
			     icd_srv_disconnect_cb_fn disconnect_cb,
			     gpointer disconnect_cb_token, gpointer * private)
{
	ILOG_DEBUG("tor_disconnect: %s\n", network_id);
    provider_tor_private* priv = *private;

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
		identify_cb(ICD_SRV_IDENTIFIED,
                TOR_PROVIDER_TYPE,	/* service type */
			    name,
                0,	/* XXX: service attributes */
			    TOR_PROVIDER_ID, /* TODO: replace this with what is in gconf */
                0,	/* XXX: service priority */
			    network_type,
			    network_attrs, network_id, identify_cb_token);

	} else {
		ILOG_DEBUG("tor_identify: NO MATCH\n");
        /* TODO: Do we really need to add provider type and provider id when we
         * don't match it? */
		identify_cb(ICD_SRV_UNKNOWN,
                TOR_PROVIDER_TYPE,	/* service type */
			    name,
                0,	/* XXX: service attributes */
			    TOR_PROVIDER_ID, /* TODO: replace this with what is in gconf */
                0,	/* XXX: service priority */
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
    GSList *l;
    provider_tor_private* priv = *private;
    tor_network_data* network_data;


    enum pidtype {UNKNOWN, TOR_PID, WAIT_FOR_TOR_PID};

    int pid_type = UNKNOWN;

    for (l = priv->network_data_list; l; l = l->next)
    {
        network_data = (tor_network_data *)l->data;
        if (network_data)
        {
            if (network_data->tor_pid == pid) {
                pid_type = TOR_PID; 
                break;
            }
            if (network_data->wait_for_tor_pid == pid) {
                pid_type = WAIT_FOR_TOR_PID; 
                break;
            }
            /* Do we want to do anything with unknown pids? */

        }
        else {
            /* This can happen if we are manually disconnecting, and we already
               free the network data and kill tor, then we won't have the
               network_data anymore */
            ILOG_DEBUG("tor_child_exit: network_data_list contains empty network_data");
        }
    }

    if (!l) {
        ILOG_ERR("tor_child_exit: got pid %d but did not find network_data\n", pid);
        return;
    }

    if (pid_type == TOR_PID) {
        /* If we get here, we probably did not kill Tor ourselves, since we
         * typically remove the network_data right after that, so we will also
         * (always) issue priv->close_fn here */
        network_data->tor_pid = 0;

        ILOG_DEBUG("tor_child_exit for pid: %d\n", pid);
        ILOG_INFO("Tor process stopped");

        priv->close_fn(ICD_SRV_ERROR, "Tor process quit (unexpectedly)",
                network_data->service_type,
                network_data->service_attrs,
                network_data->service_id,
                network_data->network_type,
                network_data->network_attrs,
                network_data->network_id);

        network_stop_all(network_data);
        network_free_all(network_data);

    } else if (pid_type == WAIT_FOR_TOR_PID) {
        network_data->wait_for_tor_pid = 0;
        ILOG_INFO("Got wait-for-tor pid: %d with status %d", pid, exit_status);

        if (exit_status == 0) {
            network_data->connect_cb(ICD_SRV_SUCCESS, NULL, network_data->connect_cb_token);
        } else {
            ILOG_WARN("wait-for-tor failed with %d\n", exit_status);
            network_data->connect_cb(ICD_SRV_ERROR, NULL, network_data->connect_cb_token);
            /* This will make icd2 issue disconnect, so we don't free/stop here */
        }
    }

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

	ILOG_DEBUG("tor_srv_destruct: priv %p\n", priv);

    // TODO: Free network_data, kill pids and such
    //g_free(priv);
    //private = NULL;

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
    provider_tor_private *priv = g_new0(provider_tor_private, 1);

	ILOG_DEBUG("icd_srv_init\n");

	srv_api->version = ICD_SRV_MODULE_VERSION;
	srv_api->private = priv;
	srv_api->connect = tor_connect;
	srv_api->disconnect = tor_disconnect;
	srv_api->identify = tor_identify;
	srv_api->child_exit = tor_child_exit;
	srv_api->srv_destruct = tor_srv_destruct;

    priv->watch_cb = watch_cb;
    priv->watch_cb_token = watch_cb_token;

    priv->close_fn = close;
    priv->limited_conn_fn = limited_conn;

	return TRUE;
}
