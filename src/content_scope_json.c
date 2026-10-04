/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "content_scope.h"
#include "format.h"
#include "json.h"
#include <string.h>
static int empty_info(const struct vau_file_info *i) {
    return !(i->bytes || i->mode || i->attributes || i->kind || i->year || i->month || i->day || i->hour ||
             i->minute || i->second || i->microsecond);
}
int vau_content_path_observation_valid(const struct vau_content_path_observation *o) {
    if (!o)
        return 0;
    if (o->state == VAU_STATE_UNKNOWN)
        return o->error != 0 && empty_info(&o->info);
    if (o->error)
        return 0;
    if (o->state == VAU_STATE_MISSING)
        return empty_info(&o->info);
    const struct vau_file_info *i = &o->info;
    if (o->state != VAU_STATE_FILE && o->state != VAU_STATE_DIRECTORY && o->state != VAU_STATE_OTHER)
        return 0;
    if (i->kind != (o->state == VAU_STATE_FILE        ? VAU_FILE_REGULAR
                    : o->state == VAU_STATE_DIRECTORY ? VAU_FILE_DIRECTORY
                                                      : VAU_FILE_OTHER))
        return 0;
    if (!i->year)
        return !(i->month || i->day || i->hour || i->minute || i->second || i->microsecond);
    return i->year <= 9999 && i->month >= 1 && i->month <= 12 && i->day >= 1 && i->day <= 31 &&
           i->hour <= 23 && i->minute <= 59 && i->second <= 60 && i->microsecond <= 999999;
}
static int observation(const struct vau_content_scope_path *entry, char *out, size_t cap) {
    if (!entry)
        return vau_snprintf(out, cap, "{\"known\":false,\"exists\":null,\"reason\":\"not_observed\"}");
    const struct vau_content_path_observation *o = &entry->observation;
    if (!vau_content_path_observation_valid(o))
        return VAU_INVALID;
    if (o->state == VAU_STATE_UNKNOWN)
        return vau_snprintf(out, cap, "{\"known\":false,\"exists\":null,\"native_error\":%d}", o->error);
    if (o->state == VAU_STATE_MISSING)
        return vau_snprintf(out, cap, "{\"known\":true,\"exists\":false}");
    const struct vau_file_info *i = &o->info;
    char bytes[32] = "null", date[64] = "null";
    if (o->state == VAU_STATE_FILE)
        vau_snprintf(bytes, sizeof(bytes), "\"%llu\"", (unsigned long long)i->bytes);
    if (i->year)
        vau_snprintf(date, sizeof(date), "\"%04u-%02u-%02uT%02u:%02u:%02u.%06u\"", i->year, i->month, i->day,
                     i->hour, i->minute, i->second, i->microsecond);
    return vau_snprintf(out, cap,
                        "{\"known\":true,\"exists\":true,\"kind\":\"%s\",\"bytes\":%s,\"stat_bytes\":\"%"
                        "llu\",\"modified\":%s,\"mode\":%u,\"attributes\":%u}",
                        o->state == VAU_STATE_FILE        ? "file"
                        : o->state == VAU_STATE_DIRECTORY ? "directory"
                                                          : "other",
                        bytes, (unsigned long long)i->bytes, date, i->mode, i->attributes);
}
static int valid(const struct vau_content_scope_path *entry) {
    if (!entry)
        return 1;
    char normalized[VAU_PATH_MAX];
    return memchr(entry->path, 0, sizeof(entry->path)) &&
           !vau_path_normalize(entry->path, normalized, sizeof(normalized)) &&
           !strcmp(entry->path, normalized) && vau_content_path_role_name(entry->role) && entry->root <= 1 &&
           vau_content_path_observation_valid(&entry->observation);
}
static int same(const struct vau_file_info *a, const struct vau_file_info *b) {
    return a->bytes == b->bytes && a->mode == b->mode && a->attributes == b->attributes &&
           a->kind == b->kind && a->year == b->year && a->month == b->month && a->day == b->day &&
           a->hour == b->hour && a->minute == b->minute && a->second == b->second &&
           a->microsecond == b->microsecond;
}
int vau_content_scope_changes_json(const struct vau_content_scope_path *before,
                                   const struct vau_content_scope_path *after, char *out, size_t cap) {
    if (!out || !cap)
        return VAU_INVALID;
    out[0] = 0;
    if ((!before && !after) || !valid(before) || !valid(after))
        return VAU_INVALID;
    if (before && after && (strcmp(before->path, after->path) || before->role != after->role))
        return VAU_STALE;
    const struct vau_content_scope_path *entry = before ? before : after;
    char path[VAU_PATH_MAX * 2 + 3], left[384], right[384];
    if (vau_json_quote(entry->path, path, sizeof(path)) < 0)
        return VAU_UNSUPPORTED;
    int n = observation(before, left, sizeof(left));
    if (n < 0 || (size_t)n >= sizeof(left))
        return VAU_UNSUPPORTED;
    n = observation(after, right, sizeof(right));
    if (n < 0 || (size_t)n >= sizeof(right))
        return VAU_UNSUPPORTED;
    const char *change = "unknown";
    if (before && after && before->observation.state != VAU_STATE_UNKNOWN &&
        after->observation.state != VAU_STATE_UNKNOWN) {
        unsigned a = before->observation.state, b = after->observation.state;
        if (a == VAU_STATE_MISSING && b != VAU_STATE_MISSING)
            change = "created";
        else if (a != VAU_STATE_MISSING && b == VAU_STATE_MISSING)
            change = "removed";
        else if (a == VAU_STATE_MISSING && b == VAU_STATE_MISSING)
            change = "still_absent";
        else
            change = a == b && same(&before->observation.info, &after->observation.info)
                         ? "metadata_unchanged"
                         : "metadata_changed";
    }
    n = vau_snprintf(out, cap,
                     "{\"path\":%s,\"role\":\"%s\",\"root\":%s,\"planned_preservation\":%s,\"before\":%s,"
                     "\"after\":%s,\"change\":\"%s\"}",
                     path, vau_content_path_role_name(entry->role),
                     ((before && before->root) || (after && after->root)) ? "true" : "false",
                     entry->role == VAU_CONTENT_SHARED_SAVEDATA ||
                             entry->role == VAU_CONTENT_SHARED_GAMEDATA ||
                             entry->role == VAU_CONTENT_MEDIA_DATABASE
                         ? "true"
                         : "false",
                     left, right, change);
    if (n < 0 || (size_t)n >= cap) {
        out[0] = 0;
        return VAU_UNSUPPORTED;
    }
    return n;
}
