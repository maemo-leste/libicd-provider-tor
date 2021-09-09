#include <glib.h>

#include "libicd_tor.h"
#include "dbus_tor.h"
#include "dbus_tor.h"
#include "libicd_network_tor.h"

DBusHandlerResult start_callback(DBusConnection * connection,
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

DBusHandlerResult getstatus_callback(DBusConnection * connection,
				     DBusMessage * message, void *user_data)
{
	const char *state = NULL;
	network_tor_private *priv = user_data;

	DBusMessage *reply = dbus_message_new_method_return(message);
	if (!reply) {
		ILOG_WARN("icd_dbus_send_system_msg failed");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	/* TODO: DRY this */
	if (!priv->state.tor_running) {
		state = ICD_TOR_SIGNALS_STATUS_STOPPED;
	} else {
		if (priv->state.tor_bootstrapped) {
			state = ICD_TOR_SIGNALS_STATUS_CONNECTED;
		} else {
			state = ICD_TOR_SIGNALS_STATUS_STARTED;
		}
	}

	dbus_message_append_args(reply,
				 DBUS_TYPE_STRING, &state, DBUS_TYPE_INVALID);

	if (icd_dbus_send_system_msg(reply) == FALSE) {
		ILOG_WARN("icd_dbus_send_system_msg failed");
		dbus_message_unref(reply);

		return DBUS_HANDLER_RESULT_HANDLED;
	}

	dbus_message_unref(reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

void emit_status_signal(network_tor_state state)
{
	const char *status = NULL;
	DBusMessage *msg = NULL;

	msg =
	    dbus_message_new_signal(ICD_TOR_DBUS_PATH, ICD_TOR_DBUS_INTERFACE,
				    "StatusChanged");
	if (msg == NULL) {
		ILOG_WARN
		    ("Could not construct dbus message for StatusChanged signal");
		return;
	}

	/* TODO: DRY this */
	if (!state.tor_running) {
		status = ICD_TOR_SIGNALS_STATUS_STOPPED;
	} else {
		if (state.tor_bootstrapped) {
			status = ICD_TOR_SIGNALS_STATUS_CONNECTED;
		} else {
			status = ICD_TOR_SIGNALS_STATUS_STARTED;
		}
	}

	dbus_message_append_args(msg,
				 DBUS_TYPE_STRING, &status, DBUS_TYPE_INVALID);

	icd_dbus_send_system_msg(msg);

	dbus_message_unref(msg);
}
