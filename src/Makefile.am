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
	libicd_provider_tor.la

libicd_provider_tor_la_SOURCES = \
	libicd_provider_tor.c
