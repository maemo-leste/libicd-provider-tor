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

#ifndef __LIBICD_TOR_SHARED_H
#define __LIBICD_TOR_SHARED_H

#define TOR_NETWORK_TYPE "TOR"
#define TOR_PROVIDER_TYPE "TOR"
#define TOR_PROVIDER_NAME "Tor Provider"

#define TOR_DEFAULT_SERVICE_ATTRIBUTES 0
#define TOR_DEFAULT_SERVICE_PRIORITY 0

#define GC_TOR "/system/osso/connectivity/providers/tor"
#define GC_ICD_TOR_AVAILABLE_IDS "/system/osso/connectivity/srv_provider/TOR/available_ids"

#define GC_NETWORK_TYPE "/system/osso/connectivity/network_type/TOR"
#define GC_TOR_ACTIVE  GC_NETWORK_TYPE"/active_config"
#define GC_TOR_SYSTEM  GC_NETWORK_TYPE"/system_wide_enabled"

#define GC_TPENABLED       "transproxy-enabled"
#define GC_SOCKSPORT       "socks-port"
#define GC_CONTROLPORT     "control-port"
#define GC_TRANSPORT       "trans-port"
#define GC_DNSPORT         "dns-port"
#define GC_DATADIR         "datadir"
#define GC_RUNDIR          "rundir"
#define GC_BRIDGES         "bridges"
#define GC_BRIDGESENABLED  "bridges-enabled"
#define GC_HIDDENSERVICES  "hiddenservices"
#define GC_HSENABLED       "hiddenservices-enabled"

#define ICD_TOR_DBUS_INTERFACE "org.maemo.Tor"
#define ICD_TOR_DBUS_PATH "/org/maemo/Tor"

#define ICD_TOR_METHOD_GETSTATUS ICD_TOR_DBUS_INTERFACE".GetStatus"

#define ICD_TOR_SIGNAL_STATUSCHANGED      "StatusChanged"
#define ICD_TOR_SIGNAL_STATUSCHANGED_FILTER "member='" ICD_TOR_SIGNAL_STATUSCHANGED "'"

#define ICD_TOR_SIGNALS_STATUS_STATE_CONNECTED "Connected"
#define ICD_TOR_SIGNALS_STATUS_STATE_STARTED "Started"
#define ICD_TOR_SIGNALS_STATUS_STATE_STOPPED "Stopped"

#define ICD_TOR_SIGNALS_STATUS_MODE_NORMAL "Normal"
#define ICD_TOR_SIGNALS_STATUS_MODE_PROVIDER "Provider"

enum TOR_DBUS_METHOD_START_RESULT {
	TOR_DBUS_METHOD_START_RESULT_OK,
	TOR_DBUS_METHOD_START_RESULT_FAILED,
	TOR_DBUS_METHOD_START_RESULT_INVALID_CONFIG,
	TOR_DBUS_METHOD_START_RESULT_INVALID_ARGS,
	TOR_DBUS_METHOD_START_RESULT_ALREADY_RUNNING,
	TOR_DBUS_METHOD_START_RESULT_REFUSED,
};

enum TOR_DBUS_METHOD_STOP_RESULT {
	TOR_DBUS_METHOD_STOP_RESULT_OK,
	TOR_DBUS_METHOD_STOP_RESULT_NOT_RUNNING,
	TOR_DBUS_METHOD_STOP_RESULT_REFUSED,
};

#endif				/* __LIBICD_TOR_SHARED_H */
