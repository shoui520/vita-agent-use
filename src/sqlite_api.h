/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_SQLITE_API_H
#define VAU_SQLITE_API_H

/*
 * The firmware's own SQLite (SceSqlite, imported through native365.yml), not a
 * bundled copy. Only the entry points declared here are resolved, and sqlite3.h
 * is never included, so callers use raw result codes:
 *
 *   0   SQLITE_OK      100 SQLITE_ROW      101 SQLITE_DONE
 *
 * Failures are surfaced as -65536 - code, which keeps them apart from both the
 * small VAU_* codes and Sony's 0x8xxxxxxx errors in replies and audit records.
 */
typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
extern int sqlite3_open_v2(const char *, sqlite3 **, int, const char *);
extern int sqlite3_close(sqlite3 *);
extern int sqlite3_prepare_v2(sqlite3 *, const char *, int, sqlite3_stmt **, const char **);
extern int sqlite3_bind_text(sqlite3_stmt *, int, const char *, int, void (*)(void *));
extern int sqlite3_step(sqlite3_stmt *);
extern const unsigned char *sqlite3_column_text(sqlite3_stmt *, int);
extern int sqlite3_column_type(sqlite3_stmt *, int);
extern const void *sqlite3_column_blob(sqlite3_stmt *, int);
extern int sqlite3_column_bytes(sqlite3_stmt *, int);
extern int sqlite3_finalize(sqlite3_stmt *);
extern int sqlite3_exec(sqlite3 *, const char *, int (*)(void *, int, char **, char **), void *,
                        char **);

#endif
