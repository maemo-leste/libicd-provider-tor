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

#include <stdio.h>

#include <glib.h>
#include <gconf/gconf-client.h>

#include "libicd_tor.h"

gboolean get_system_wide_enabled(void) {
	GConfClient *gconf;
    gboolean enabled = FALSE;

	gconf = gconf_client_get_default();

	enabled = gconf_client_get_bool(gconf, GC_TOR_SYSTEM, NULL);

	g_object_unref(gconf);

    return enabled;
}

char* get_active_config(void) {
	GConfClient *gconf;
    char* active_config = NULL;

	gconf = gconf_client_get_default();

	active_config = gconf_client_get_string(gconf, GC_TOR_ACTIVE, NULL);

	g_object_unref(gconf);

    return active_config;
}

char* generate_config(const char* config_name) {
	GConfClient *gconf;
	gchar *torrc;
	gboolean bridges_enabled, hs_enabled;
	gint socks_port, control_port, trans_port, dns_port;
	gchar *datadir, *bridges, *hiddenservices;

	gconf = gconf_client_get_default();

	gchar *gc_socksport =
	    g_strjoin("/", GC_TOR, config_name, GC_SOCKSPORT, NULL);
	socks_port = gconf_client_get_int(gconf, gc_socksport, NULL);
	g_free(gc_socksport);

	gchar *gc_controlport =
	    g_strjoin("/", GC_TOR, config_name, GC_CONTROLPORT, NULL);
	control_port = gconf_client_get_int(gconf, gc_controlport, NULL);
	g_free(gc_controlport);

	gchar *gc_transport =
	    g_strjoin("/", GC_TOR, config_name, GC_TRANSPORT, NULL);
	trans_port = gconf_client_get_int(gconf, gc_transport, NULL);
	g_free(gc_transport);

	gchar *gc_dnsport =
	    g_strjoin("/", GC_TOR, config_name, GC_DNSPORT, NULL);
	dns_port = gconf_client_get_int(gconf, gc_dnsport, NULL);
	g_free(gc_dnsport);

	gchar *gc_datadir =
	    g_strjoin("/", GC_TOR, config_name, GC_DATADIR, NULL);
	datadir = gconf_client_get_string(gconf, gc_datadir, NULL);
	g_free(gc_datadir);

	gchar *gc_bridgesenabled =
	    g_strjoin("/", GC_TOR, config_name, GC_BRIDGESENABLED, NULL);
	bridges_enabled = gconf_client_get_bool(gconf, gc_bridgesenabled, NULL);
	g_free(gc_bridgesenabled);

	if (bridges_enabled) {
		gchar *gc_bridges =
		    g_strjoin("/", GC_TOR, config_name, GC_BRIDGES, NULL);
		bridges = gconf_client_get_string(gconf, gc_bridges, NULL);
		g_free(gc_bridges);
	} else {
		bridges = "";
	}

	gchar *gc_hsenabled =
	    g_strjoin("/", GC_TOR, config_name, GC_HSENABLED, NULL);
	hs_enabled = gconf_client_get_bool(gconf, gc_hsenabled, NULL);
	g_free(gc_hsenabled);

	if (hs_enabled) {
		gchar *gc_hiddenservices =
		    g_strjoin("/", GC_TOR, config_name, GC_HIDDENSERVICES,
			      NULL);
		hiddenservices =
		    gconf_client_get_string(gconf, gc_hiddenservices, NULL);
		g_free(gc_hiddenservices);
	} else {
		hiddenservices = "";
	}

	g_object_unref(gconf);

	torrc = g_strdup_printf(
        /* "User debian-tor\n" */
		"SocksPort %d\n"
		"ControlPort %d\n"
		"VirtualAddrNetworkIPv4 10.192.0.0/10\n"
		"AutomapHostsOnResolve 1\n"
		"TransPort %d IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort\n"
		"DNSPort %d\n"
		"CookieAuthentication 1\n"
		"DataDirectory %s\n" "%s\n"	/* bridges */
		"%s\n",	/* hiddenservices */
		socks_port,
		control_port,
		trans_port,
		dns_port,
		datadir,
		bridges,
		hiddenservices
	);

	return torrc;
}
