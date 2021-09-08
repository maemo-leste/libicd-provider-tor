#ifndef __LIBICD_TOR_H
#define __LIBICD_TOR_H

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

#define GC_SOCKSPORT       "socks-port"
#define GC_CONTROLPORT     "control-port"
#define GC_TRANSPORT       "trans-port"
#define GC_DNSPORT         "dns-port"
#define GC_DATADIR         "datadir"
#define GC_BRIDGES         "bridges"
#define GC_BRIDGESENABLED  "bridges-enabled"
#define GC_HIDDENSERVICES  "hiddenservices"
#define GC_HSENABLED       "hiddenservices-enabled"

gboolean get_system_wide_enabled(void);
char* generate_config(const char* config_name);
char* get_active_config(void);


#endif /* __LIBICD_TOR_H */
