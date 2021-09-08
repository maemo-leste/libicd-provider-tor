MAINTAINERCLEANFILES = \
	Makefile.in

INCLUDES = \
	@GLIB_CFLAGS@ \
	@GCONF_CFLAGS@ \
	@ICD2_CFLAGS@ \
	@OSSO_IC_DEV_CFLAGS@

LDFLAGS = -avoid-version

plugindir = @ICD_PLUGIN_DIR@

plugin_LTLIBRARIES = \
	libicd_provider_tor.la \
	libicd_network_tor.la

libicd_provider_tor_la_SOURCES = \
	libicd_provider_tor.c \
	libicd_tor_config.c \
	libicd_tor.h

libicd_network_tor_la_SOURCES = \
	libicd_network_tor.c \
	dbus_tor.c \
	dbus_tor.h \
	dbus_tor_shared.h \
	libicd_tor_config.c \
	libicd_tor.h
