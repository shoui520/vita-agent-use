/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_SQLITE_JSON_H
#define VAU_SQLITE_JSON_H

#include "sqlite_api.h"
#include <stddef.h>

void vau_sqlite_json_reset(void);
int vau_vita_metadata_error(void *, char *, size_t);
int vau_sqlite_json_column(sqlite3_stmt *, int, char *, size_t, int);

#endif
