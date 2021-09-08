#include <dbus/dbus-glib-lowlevel.h>

#include "libicd_tor.h"
#include "icd/support/icd_dbus.h"
#include "icd/support/icd_log.h"
#include "dbus_tor.h"

#include <stdio.h>

struct tor_method_callbacks {
	const gchar *method_name;
	DBusHandleMessageFunction call;
};

static DBusHandlerResult start_callback(DBusConnection * connection,
					DBusMessage * message, void *user_data);
static DBusHandlerResult error_callback(DBusConnection * connection,
					DBusMessage * message, void *user_data);

static struct tor_method_callbacks callbacks[] = {
	{"Start", &start_callback},
	{"Stop", &error_callback},
	{"GetStatus", &error_callback},
	{"GetActiveConfig", &error_callback},
	/*
	   {"Stop", &stop_callback},
	   {"GetStatus", &getstatus_callback},
	   {"GetActiveConfig", &getactiveconfig_callback},
	 */

	{NULL,}
};

/**
 * Receive registered method calls and find a handler for them
 *
 * @param connection  D-Bus connection
 * @param message     D-Bus message
 * @param user_data   dbus api data structure
 */
static DBusHandlerResult
tor_icd_dbus_api_request(DBusConnection * connection, DBusMessage * message,
			 void *user_data)
{
	ILOG_DEBUG("ICD2 Tor dbus api request\n");

	const char *iface = dbus_message_get_interface(message);
	const char *member = dbus_message_get_member(message);
	const char *signature = dbus_message_get_signature(message);

	fprintf(stderr, "iface: %s\n", iface);
	fprintf(stderr, "member: %s\n", member);
	fprintf(stderr, "signature: %s\n", signature);

	int i = 0;

	while (callbacks[i].method_name != NULL) {
		if (strcmp(member, callbacks[i].method_name) == 0) {
			ILOG_DEBUG("Match for method %s", member);
			return callbacks[i].call(connection, message,
						 user_data);
		}

		i++;
	}
	return error_callback(connection, message, user_data);
}


static DBusHandlerResult error_callback(DBusConnection * connection,
					DBusMessage * message, void *user_data)
{
	DBusMessage *err_msg;

	ILOG_INFO("received '%s.%s' request has no handler implemented",
		  dbus_message_get_interface(message),
		  dbus_message_get_member(message));

	err_msg = dbus_message_new_error(message, DBUS_ERROR_NOT_SUPPORTED,
					 "Unsupported interface or method");
	icd_dbus_send_system_msg(err_msg);
	dbus_message_unref(err_msg);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult start_callback(DBusConnection * connection,
					DBusMessage * message, void *user_data)
{
	DBusMessage *reply = dbus_message_new_method_return(message);
	if (!reply) {
        ILOG_WARN("icd_dbus_send_system_msg failed");
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}
	dbus_int32_t success_code = TOR_DBUS_METHOD_START_RESULT_OK;
	dbus_message_append_args(reply,
				 DBUS_TYPE_INT32, &success_code,
				 DBUS_TYPE_INVALID);

	if (icd_dbus_send_system_msg(reply) == FALSE) {
        ILOG_WARN("icd_dbus_send_system_msg failed");
        dbus_message_unref(reply);

        return DBUS_HANDLER_RESULT_HANDLED;
	}

	dbus_message_unref(reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}


int setup_tor_dbus(void *user_data)
{
	ILOG_DEBUG("Registering ICD2 Tor dbus service");
	if (icd_dbus_register_system_service(ICD_TOR_DBUS_PATH,
					     ICD_TOR_DBUS_INTERFACE,
					     DBUS_NAME_FLAG_REPLACE_EXISTING |
					     DBUS_NAME_FLAG_DO_NOT_QUEUE,
					     tor_icd_dbus_api_request,
					     user_data) == FALSE) {
		ILOG_ERR("Failed to register DBUS interface\n");
		return 1;
	}
	ILOG_DEBUG("Successfully registered ICD2 Tor dbus service");

	return 0;
}


int free_tor_dbus(void)
{
	icd_dbus_unregister_system_service(ICD_TOR_DBUS_PATH,
					   ICD_TOR_DBUS_INTERFACE);
	return 0;
}
