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

#ifndef __DBUS_TOR_H
#define __DBUS_TOR_H
#include "libicd_tor_shared.h"

#include <support/icd_dbus.h>
#include <support/icd_log.h>

int setup_tor_dbus(void *user_data);
int free_tor_dbus(void);

#if 0
void broadcast_status_changed(... status)
#endif
#endif
