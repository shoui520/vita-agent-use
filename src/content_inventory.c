/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "file_ops.h"
#include "format.h"
#include "json.h"
#include "native_ops.h"
#include "sfo_titles.h"
#include "sqlite_api.h"
#include "sqlite_json.h"
#include <psp2/appmgr.h>
#include <psp2/io/dirent.h>
#include <string.h>

#ifdef VAU_NATIVE_FORMAT
#include "sqlite_memory.h"
#endif
static int category(const char *name) {
    return !strcmp(name, "photo")   ? 0
           : !strcmp(name, "music") ? 1
           : !strcmp(name, "video") ? 2
           : !strcmp(name, "theme") ? 3
                                    : -1;
}
int vau_content_inventory(const char *path, const char *kind, const char *after, char *out, size_t cap) {
    if (!path || !kind || !after || !out || cap < 3500)
        return VAU_INVALID;
    int k = category(kind);
    if (k < 0)
        return VAU_UNSUPPORTED;
    if (strlen(after) > 19 || (after[0] == '0' && after[1]))
        return VAU_INVALID;
    for (const char *p = after; *p; p++)
        if (*p < '0' || *p > '9')
            return VAU_INVALID;
    const char *cursor = after[0] ? after : "0";
    struct vau_json_token token = {0, strlen(cursor), 0, VAU_JSON_NUMBER};
    uint64_t number;
    if (vau_json_u64(cursor, &token, &number) || number > INT64_MAX)
        return VAU_INVALID;
#ifdef VAU_NATIVE_FORMAT
    int configured = vau_sqlite_memory_configure();
    if (configured)
        return configured;
#endif
    static const char *queries[] = {
        "SELECT mrid,title,content_path,size,created_time,'','' FROM tbl_VPContent WHERE content_type=4 AND "
        "status=2 AND content_path IS NOT NULL AND mrid>CAST(?1 AS INTEGER) ORDER BY mrid LIMIT 2",
        "SELECT mrid,title,content_path,size,imported_time,artist,album_name FROM tbl_Music WHERE status=2 "
        "AND content_path IS NOT NULL AND mrid>CAST(?1 AS INTEGER) ORDER BY mrid LIMIT 2",
        "SELECT mrid,title,content_path,size,created_time,'','' FROM tbl_VPContent WHERE content_type=5 AND "
        "status=2 AND content_path IS NOT NULL AND mrid>CAST(?1 AS INTEGER) ORDER BY mrid LIMIT 2",
        "SELECT "
        "rowid,id,size,lastModifiedTime,type,packageImageFilePath,homePreviewFilePath,startPreviewFilePath,"
        "titleDefault,providerDefault FROM tbl_theme WHERE rowid>CAST(?1 AS INTEGER) ORDER BY rowid LIMIT 2"};
    vau_sqlite_json_reset();
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int n = 0;
    int rc = sqlite3_open_v2(path, &db, 1, NULL);
    if (rc)
        goto done;
    rc = sqlite3_exec(db, "PRAGMA cache_size=32", NULL, NULL, NULL);
    if (rc)
        goto done;
    rc = sqlite3_prepare_v2(db, queries[k], -1, &stmt, NULL);
    if (rc)
        goto done;
    rc = sqlite3_bind_text(stmt, 1, cursor, -1, NULL);
    if (rc)
        goto done;
    n = vau_snprintf(
        out, cap,
        "{\"source\":\"native_content_database\",\"category\":\"%s\",\"snapshot\":false,\"entries\":[", kind);
    if (n < 0 || (size_t)n >= cap) {
        rc = VAU_DEVICE_ERROR;
        goto done;
    }
    char next[21];
    memcpy(next, cursor, strlen(cursor) + 1);
    unsigned count = 0, more = 0;
    static const char *media_fields[] = {"id", "title", "path", "bytes", "created", "artist", "album"};
    static const char *theme_fields[] = {
        "id",           "theme_id",      "bytes",         "modified",        "type", "package_image",
        "home_preview", "start_preview", "title_default", "provider_default"};
    const char *const *fields = k == 3 ? theme_fields : media_fields;
    unsigned field_count = k == 3 ? 10 : 7;
    while ((rc = sqlite3_step(stmt)) == 100) {
        if (count) {
            more = 1;
            rc = 0;
            break;
        }
        if ((size_t)n + 2 >= cap) {
            rc = VAU_DEVICE_ERROR;
            goto done;
        }
        out[n++] = '{';
        for (unsigned i = 0; i < field_count; i++) {
            if (i == 0) {
                const unsigned char *text = sqlite3_column_text(stmt, 0);
                int size = sqlite3_column_bytes(stmt, 0);
                struct vau_json_token id = {0, (size_t)(size > 0 ? size : 0), 0, VAU_JSON_NUMBER};
                uint64_t value;
                if (!text || !size || size > 19 || vau_json_u64((const char *)text, &id, &value) ||
                    value <= number || value > INT64_MAX) {
                    rc = VAU_DEVICE_ERROR;
                    goto done;
                }
                memcpy(next, text, (size_t)size);
                next[size] = 0;
            }
            int added = vau_snprintf(out + n, cap - (size_t)n, "%s\"%s\":", i ? "," : "", fields[i]);
            if (added < 0 || (size_t)added >= cap - (size_t)n) {
                rc = VAU_UNSUPPORTED;
                goto done;
            }
            n += added;
            added = vau_sqlite_json_column(stmt, (int)i, out + n, cap - (size_t)n, 1);
            if (added < 0) {
                rc = added;
                goto done;
            }
            n += added;
            if ((size_t)n + 100 >= cap) {
                rc = VAU_UNSUPPORTED;
                goto done;
            }
        }
        out[n++] = '}';
        count++;
    }
    if (rc == 101)
        rc = 0;
    if (!rc) {
        int added = vau_snprintf(out + n, cap - (size_t)n, "],\"next_after\":\"%s\",\"more\":%s}", next,
                                 more ? "true" : "false");
        if (added < 0 || (size_t)added >= cap - (size_t)n)
            rc = VAU_DEVICE_ERROR;
        else
            n += added;
    }
done:
    if (stmt) {
        int end = sqlite3_finalize(stmt);
        if (!rc && end)
            rc = end;
    }
    if (db) {
        int end = sqlite3_close(db);
        if (!rc && end)
            rc = end;
    }
    return rc ? rc < 0 ? rc : VAU_DEVICE_ERROR : n;
}
int vau_vita_content_inventory(void *ctx, const char *kind, const char *after, char *out, size_t cap) {
    (void)ctx;
#ifdef VAU_NATIVE_FORMAT
    if (vau_content_legacy_category(kind) >= 0)
        return vau_content_legacy_inventory(kind, after, out, cap);
#endif
    int k = category(kind);
    if (k < 0)
        return VAU_UNSUPPORTED;
    static const char *paths[] = {"ux0:/mms/photo/AVContent.db", "ux0:/mms/music/AVContent.db",
                                  "ux0:/mms/video/AVContent.db", "ur0:shell/db/app.db"};
    return vau_content_inventory(paths[k], kind, after, out, cap);
}

/* One service-owned iterator; no allocation proportional to catalog size. */
static struct {
    int fd, category, pending;
    char mount[16];
    uint32_t position;
    uint64_t used_us;
    SceIoDirent entry;
    struct vau_file_info directory;
} listing = {.fd = -1};
static uint64_t listing_clock;
int vau_content_legacy_reset(void) {
    if (listing.fd >= 0) {
        int rc = sceIoDclose(listing.fd);
        if (rc < 0)
            return rc;
        listing.fd = -1;
    }
    if (listing.mount[0]) {
        int rc = sceAppMgrUmount(listing.mount);
        if (rc < 0)
            return rc;
    }
    memset(&listing, 0, sizeof(listing));
    listing.fd = -1;
    return VAU_OK;
}
void vau_content_legacy_idle(uint64_t now) {
    listing_clock = now;
    if (listing.fd >= 0 && (now < listing.used_us || now - listing.used_us >= UINT64_C(30000000)))
        (void)vau_content_legacy_reset();
}

int vau_content_legacy_category(const char *kind) {
    static const char *const categories[] = {"psp_application", "playstation_application", "psp_savedata",
                                             "playstation_savedata"};
    if (!kind)
        return -1;
    for (unsigned i = 0; i < 4; i++)
        if (!strcmp(kind, categories[i]))
            return (int)i;
    return -1;
}
/* 3.65 Content Manager classifier8101ccdc. The native thread constructors
 * label the positive branch Ps1 and the complementary branch Psp/Other. */
static int playstation(const char *name) {
    if (strlen(name) != 9 || (name[0] != 'P' && name[0] != 'S'))
        return 0;
    for (unsigned i = 1; i < 4; i++)
        if (name[i] < 'A' || name[i] > 'Z')
            return 0;
    for (unsigned i = 4; i < 9; i++)
        if (name[i] < '0' || name[i] > '9')
            return 0;
    return 1;
}
int vau_content_legacy_inventory(const char *kind, const char *after, char *out, size_t cap) {
    int category = vau_content_legacy_category(kind);
    if (category < 0)
        return VAU_UNSUPPORTED;
    if (!after || !out || cap < 3500 || strlen(after) > 10 || (after[0] == '0' && after[1]))
        return VAU_INVALID;
    uint32_t cursor = 0;
    for (const char *p = after; *p; p++) {
        if (*p < '0' || *p > '9' || cursor > UINT32_MAX / 10 ||
            (cursor == UINT32_MAX / 10 && (unsigned)(*p - '0') > UINT32_MAX % 10))
            return VAU_INVALID;
        cursor = cursor * 10 + (unsigned)(*p - '0');
    }
    const char *root = category >= 2 ? "ux0:pspemu/PSP/SAVEDATA" : "ux0:pspemu/PSP/GAME";
    struct vau_file_info directory = {0};
    int rc = 0;
    if (!cursor) {
        rc = vau_content_legacy_reset();
        if (rc < 0)
            return rc;
        char mount[16] = {0};
        rc = sceAppMgrWorkDirMount(0xca, mount);
        if (rc < 0)
            return rc;
        if (!memchr(mount, 0, sizeof(mount)) || !mount[0])
            return VAU_DEVICE_ERROR;
        memcpy(listing.mount, mount, sizeof(mount));
        rc = vau_vita_file_stat(NULL, root, &directory);
        if (!rc && directory.kind != VAU_FILE_DIRECTORY)
            rc = VAU_INVALID;
        if (!rc) {
            listing.fd = sceIoDopen(root);
            if (listing.fd < 0)
                rc = listing.fd;
        }
        if (rc < 0) {
            (void)vau_content_legacy_reset();
            return rc;
        }
        listing.category = category;
        listing.directory = directory;
    } else {
        if (listing.fd < 0 || listing.category != category || listing.position != cursor)
            return VAU_STALE;
        rc = vau_vita_file_stat(NULL, root, &directory);
        const struct vau_file_info *old = &listing.directory;
        if (rc < 0 || old->bytes != directory.bytes || old->mode != directory.mode ||
            old->attributes != directory.attributes || old->kind != directory.kind ||
            old->year != directory.year || old->month != directory.month || old->day != directory.day ||
            old->hour != directory.hour || old->minute != directory.minute ||
            old->second != directory.second || old->microsecond != directory.microsecond) {
            (void)vau_content_legacy_reset();
            return rc < 0 ? rc : VAU_STALE;
        }
    }
    listing.used_us = listing_clock;
    int n = vau_snprintf(out, cap,
                         "{\"source\":\"native_content_manager_directory_enumeration\",\"category\":\"%s\","
                         "\"path\":\"%s\",\"snapshot\":false,\"entries\":[",
                         kind, root);
    if (n < 0 || (size_t)n >= cap) {
        rc = VAU_DEVICE_ERROR;
        goto done;
    }
    uint32_t next = cursor, reads = 0;
    int count = 0, more = 0;
    for (;;) {
        if (reads == 128 || count == 8) {
            more = 1;
            rc = 0;
            break;
        }
        if (!listing.pending) {
            memset(&listing.entry, 0, sizeof(listing.entry));
            ++reads;
            rc = sceIoDread(listing.fd, &listing.entry);
            if (rc <= 0)
                break;
            if (!memchr(listing.entry.d_name, 0, sizeof(listing.entry.d_name)) ||
                listing.position == UINT32_MAX) {
                rc = VAU_DEVICE_ERROR;
                break;
            }
            listing.pending = 1;
        }
        SceIoDirent entry = listing.entry;
        uint32_t position = listing.position + 1;
        if (!strcmp(entry.d_name, ".") || !strcmp(entry.d_name, "..") || !SCE_S_ISDIR(entry.d_stat.st_mode) ||
            SCE_S_ISLNK(entry.d_stat.st_mode) || !strcmp(entry.d_name, "sce_sys") ||
            !strcmp(entry.d_name, "sce_pfs") || playstation(entry.d_name) != (category & 1)) {
            listing.position = next = position;
            listing.pending = 0;
            continue;
        }
        char path[VAU_PATH_MAX], quoted_path[VAU_PATH_MAX * 6 + 3], quoted_name[1539];
        int length = vau_snprintf(path, sizeof(path), "%s/%s", root, entry.d_name);
        if (length < 0 || (size_t)length >= sizeof(path) || strchr(entry.d_name, '/') ||
            strchr(entry.d_name, ':') || strchr(entry.d_name, '\\') ||
            vau_json_quote(path, quoted_path, sizeof(quoted_path)) < 0 ||
            vau_json_quote(entry.d_name, quoted_name, sizeof(quoted_name)) < 0) {
            rc = VAU_DEVICE_ERROR;
            break;
        }
        struct vau_sfo_titles titles = {0};
        char metadata_file[16] = {0};
        int metadata = category >= 2 ? vau_vita_savedata_titles(path, &titles)
                                     : vau_vita_application_titles(path, &titles, metadata_file);
        if (category >= 2)
            memcpy(metadata_file, "PARAM.SFO", 10);
        const char *name = entry.d_name, *name_source = "directory_id";
        if (category >= 2 && !metadata && titles.savedata_title[0]) {
            name = titles.savedata_title;
            name_source = "SAVEDATA_TITLE";
        } else if (!metadata && titles.title[0]) {
            name = titles.title;
            name_source = "TITLE";
        }
        char display[1539], detail[256], file_json[99];
        if (vau_json_quote(name, display, sizeof(display)) < 0 ||
            vau_json_quote(metadata_file, file_json, sizeof(file_json)) < 0) {
            rc = VAU_DEVICE_ERROR;
            break;
        }
        int detail_bytes = vau_snprintf(detail, sizeof(detail),
                                        ",\"name_source\":\"%s\",\"metadata_result\":%d,\"metadata_file\":%s",
                                        name_source, metadata, file_json);
        if (detail_bytes < 0 || (size_t)detail_bytes >= sizeof(detail)) {
            rc = VAU_DEVICE_ERROR;
            break;
        }
        size_t needed = strlen(quoted_path) + strlen(quoted_name) + strlen(display) + strlen(detail) + 350;
        if (needed + 80 >= cap - (size_t)n) {
            rc = count ? 0 : VAU_UNSUPPORTED;
            more = 1;
            break;
        }
        SceDateTime *date = &entry.d_stat.st_mtime;
        int added = vau_snprintf(
            out + n, cap - (size_t)n,
            "%s{\"id\":\"%u\",\"directory_id\":%s,\"name\":%s,\"path\":%s,\"kind\":\"directory\","
            "\"modified\":\"%04u-%02u-%02uT%02u:%02u:%02u.%06u\",\"bytes\":null,\"size_measured\":false%s}",
            count ? "," : "", position, quoted_name, display, quoted_path, date->year, date->month, date->day,
            date->hour, date->minute, date->second, date->microsecond, detail);
        if (added < 0 || (size_t)added + 80 >= cap - (size_t)n) {
            rc = VAU_DEVICE_ERROR;
            break;
        }
        n += added;
        listing.position = next = position;
        listing.pending = 0;
        count++;
    }
    if (!rc) {
        int added = vau_snprintf(out + n, cap - (size_t)n, "],\"next_after\":\"%u\",\"more\":%s}", next,
                                 more ? "true" : "false");
        if (added < 0 || (size_t)added >= cap - (size_t)n)
            rc = VAU_DEVICE_ERROR;
        else
            rc = n + added;
    }
done:
    if (rc < 0 || !more) {
        int ended = vau_content_legacy_reset();
        if (rc >= 0 && ended < 0)
            rc = ended;
    }
    return rc;
}
