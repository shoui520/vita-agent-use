/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "vita_agent_policy.h"
#include <string.h>

/* Vita filesystems are case-insensitive, so every policy comparison is too. */
static char lower(char c)
{
	return c >= 'A' && c <= 'Z' ? (char)(c + 'a' - 'A') : c;
}

static int same(const char *a, const char *b)
{
	while (*a && *b && lower(*a) == lower(*b)) {
		++a;
		++b;
	}

	return !*a && !*b;
}

static int under(const char *path, const char *root)
{
	while (*root && *path && lower(*root) == lower(*path)) {
		++path;
		++root;
	}

	return !*root && (!*path || *path == '/');
}

static int overlaps(const char *path, const char *root)
{
	return under(path, root) || under(root, path);
}

int vau_path_normalize(const char *path, char *out, size_t capacity)
{
	size_t n = 0, used = 0, mount = 0;

	if (!path || !out || !capacity)
		return -1;

	while (n < VAU_PATH_MAX && path[n])
		++n;
	if (!n || n == VAU_PATH_MAX || n + 1 > capacity)
		return -1;

	while (mount < n && path[mount] != ':') {
		char c = lower(path[mount]);

		if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) || mount >= 7)
			return -1;

		out[used++] = c;
		++mount;
	}

	if (!mount || mount == n)
		return -1;

	out[used++] = ':';

	size_t i = mount + 1;

	while (i < n) {
		while (i < n && path[i] == '/')
			++i;
		if (i == n)
			break;

		size_t begin = i;

		while (i < n && path[i] != '/') {
			unsigned char c = (unsigned char)path[i];

			if (c < 32 || c == 127 || c == ':' || c == '\\' || c == '*' || c == '?' || c == '%')
				return -1;

			++i;
		}

		size_t count = i - begin;

		/* Ambiguous DOS short-name forms can address a protected long-name
		 * directory or plugin without spelling its guarded name. Require the
		 * canonical long name from native directory enumeration instead. */
		for (size_t j = begin; j < i; ++j) {
			if (path[j] == '~' && j + 1 < i && path[j + 1] >= '0' && path[j + 1] <= '9') {
				size_t end = j + 1;

				while (end < i && path[end] >= '0' && path[end] <= '9')
					++end;
				if (end == i || (path[end] == '.' && i - end <= 4))
					return -1;
			}
		}

		/* Trailing '.' or ' ' can alias the trimmed name on FAT-family drivers
		 * (letting "tai." dodge the guard on "tai"); '.' and '..' are never needed. */
		if (path[i - 1] == '.' || path[i - 1] == ' ' || (count == 1 && path[begin] == '.') ||
		    (count == 2 && path[begin] == '.' && path[begin + 1] == '.')) {
			return -1;
		}

		if (used > mount + 1)
			out[used++] = '/';
		memcpy(out + used, path + begin, count);
		used += count;
	}

	out[used] = 0;
	return 0;
}

static int mount_is(const char *p, const char *mount)
{
	size_t n = strlen(mount);

	return !strncmp(p, mount, n) && (p[n] == ':' && mount[n] == 0);
}

enum vau_policy_decision vau_policy_file(enum vau_file_operation op, const char *path)
{
	static const char *const mounts[] = {
		"ux0", "ur0", "uma0", "imc0", "xmc0", "gro0", "grw0",
		"os0", "vs0", "sa0",  "pd0",  "tm0",  "ud0",  "vd0",
	};
	static const char *const managed[] = {
		"ux0:app",    "ux0:appmeta", "ux0:patch", "ux0:addcont", "ux0:license",
		"ux0:pspemu", "ux0:psm",     "ux0:user",  "ux0:picture", "ux0:music",
		"ux0:video",  "ux0:email",   "ux0:theme",
	};

	char p[VAU_PATH_MAX];
	int known = 0;

	if ((unsigned)op > VAU_FS_PURGE || vau_path_normalize(path, p, sizeof(p)))
		return VAU_POLICY_INVALID;

	for (size_t i = 0; i < sizeof(mounts) / sizeof(mounts[0]); ++i)
		known |= mount_is(p, mounts[i]);
	if (!known)
		return VAU_POLICY_INVALID;

	/* This diagnostic stream contains only fixed stage names, timestamps and
	 * integer results. Expose the exact file for readback, never its siblings. */
	if (op == VAU_FS_READ && !strcmp(p, "ur0:data/vita-agent-use/runtime.log"))
		return VAU_POLICY_ALLOW;

	/* Secrets, approvals, audit records and trash internals are accessed by
	 * dedicated operations. Ordinary file tools cannot tamper with them. */
	if (under(p, "ur0:data/vita-agent-use") || under(p, "ux0:data/vita-agent-use/control") ||
	    under(p, "ux0:data/vita-agent-use/trash")) {
		return VAU_POLICY_PROTECTED;
	}

	const char *private_relative = strchr(p, ':') + 1;

	if (under(private_relative, "data/vita-agent-use/control") ||
	    under(private_relative, "data/vita-agent-use/trash") ||
	    under(private_relative, "data/vita-agent-use/transactions")) {
		return VAU_POLICY_PROTECTED;
	}

	if (op == VAU_FS_READ)
		return VAU_POLICY_ALLOW;
	if (!mount_is(p, "ux0") && !mount_is(p, "ur0"))
		return VAU_POLICY_READ_ONLY;

	const char *relative = strchr(p, ':') + 1;

	if (!*relative)
		return VAU_POLICY_PROTECTED;
	if (overlaps(p, "ux0:tai") || overlaps(p, "ur0:tai") || overlaps(p, "ur0:shell") ||
	    overlaps(p, "ur0:data/vita-agent-use") || overlaps(p, "ux0:data/vita-agent-use/control") ||
	    overlaps(p, "ux0:data/vita-agent-use/trash")) {
		return VAU_POLICY_PROTECTED;
	}

	const char *base = strrchr(p, '/');

	base = base ? base + 1 : relative;
	if (same(base, "henkaku.skprx") || same(base, "henkaku.suprx") || same(base, "yamt.skprx") ||
	    same(base, "yamt_helper.skprx") || same(base, "storagemgr.skprx") || same(base, "app.db")) {
		return VAU_POLICY_PROTECTED;
	}

	for (size_t i = 0; i < sizeof(managed) / sizeof(managed[0]); ++i)
		if (overlaps(p, managed[i]))
			return VAU_POLICY_NATIVE_OPERATION;
	if (op == VAU_FS_PURGE || op == VAU_FS_TRASH || op == VAU_FS_RENAME_SOURCE)
		return VAU_POLICY_APPROVAL_REQUIRED;
	if (under(p, "ux0:data/vita-agent-use/workspace"))
		return VAU_POLICY_ALLOW;
	return VAU_POLICY_APPROVAL_REQUIRED;
}

int vau_policy_core_plugin(const char *name)
{
	return name &&
	       (same(name, "henkaku.suprx") || same(name, "henkaku.skprx") ||
	        same(name, "yamt_helper.skprx") || same(name, "yamt_helper.suprx") ||
	        same(name, "yamt.suprx") || same(name, "yamt.skprx") || same(name, "storagemgr.skprx"));
}

static int acl_under(const char *p, const char *root)
{
	size_t n = strlen(root);

	return under(p, root) || (n && root[n - 1] == ':' && !strncmp(p, root, n));
}

static int subject_valid(const char *s, int wildcard)
{
	if (!s)
		return 0;
	if (wildcard && !strcmp(s, "*"))
		return 1;

	for (unsigned i = 0; i < 64; ++i)
		if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
			return 0;
	return !s[64];
}

int vau_policy_validate(const struct vau_file_policy *p)
{
	if (!p || p->count > VAU_ACL_RULES_MAX || (unsigned)p->active_tai > VAU_TAI_UMA0)
		return -1;

	for (unsigned i = 0; i < p->count; ++i) {
		const struct vau_acl_rule *r = &p->rules[i];
		char normalized[VAU_PATH_MAX];

		if (!memchr(r->subject, 0, sizeof(r->subject)) || !subject_valid(r->subject, 1) ||
		    !memchr(r->path, 0, sizeof(r->path)) ||
		    vau_path_normalize(r->path, normalized, sizeof(normalized)) ||
		    strcmp(r->path, normalized) || ((r->allow | r->deny) & ~VAU_ACL_ALL) ||
		    !(r->allow | r->deny) || (r->allow & r->deny)) {
			return -1;
		}

		/* Reject unknown mounts even if no operation currently matches. */
		if (vau_policy_file(VAU_FS_READ, normalized) == VAU_POLICY_INVALID)
			return -1;
	}

	return 0;
}

enum vau_policy_decision vau_policy_evaluate(const struct vau_file_policy *policy,
                                             const char *subject, enum vau_file_operation op,
                                             const char *path, int yes)
{
	char p[VAU_PATH_MAX];

	if ((unsigned)op > VAU_FS_PURGE || (yes != 0 && yes != 1) || !subject_valid(subject, 0) ||
	    vau_policy_validate(policy) || vau_path_normalize(path, p, sizeof(p))) {
		return VAU_POLICY_INVALID;
	}

	enum vau_policy_decision baseline = vau_policy_file(VAU_FS_READ, p);

	if (baseline != VAU_POLICY_ALLOW)
		return baseline;

	int write       = op != VAU_FS_READ;
	int destructive = op == VAU_FS_TRASH || op == VAU_FS_PURGE || op == VAU_FS_RENAME_SOURCE ||
	                  op == VAU_FS_RENAME_DESTINATION;

	static const char *const immutable[] = { "os0", "pd0", "sa0", "tm0", "ud0", "vd0", "vs0" };
	for (unsigned i = 0; i < sizeof(immutable) / sizeof(*immutable); ++i)
		if (write && mount_is(p, immutable[i]))
			return VAU_POLICY_READ_ONLY;
	static const char *const tai[] = { "ur0:tai", "ux0:tai", "uma0:tai" };

	int which = -1;

	for (unsigned i = 0; i < 3; ++i) {
		if (under(p, tai[i]))
			which = (int)i;
		if (write && same(p, tai[i]))
			return VAU_POLICY_PROTECTED;
		if (destructive && (under(tai[i], p) || same(p, tai[i])))
			return VAU_POLICY_PROTECTED;
	}

	if ((write && which >= 0 && policy->active_tai == VAU_TAI_UNKNOWN) ||
	    (which == 1 && policy->active_tai != VAU_TAI_UX0) ||
	    (which == 2 && policy->active_tai != VAU_TAI_UMA0)) {
		return VAU_POLICY_PROTECTED;
	}

	const char *relative = strchr(p, ':') + 1;

	/* Other writable mount aliases cannot provide an unguarded tai root.
	 * Only the explicitly managed ur0/ux0/uma0 namespaces are supported. */
	if (write && which < 0 && under(relative, "tai"))
		return VAU_POLICY_PROTECTED;
	if (destructive && (under("data/vita-agent-use/control", relative) ||
	                    under("data/vita-agent-use/trash", relative) ||
	                    under("data/vita-agent-use/transactions", relative))) {
		return VAU_POLICY_PROTECTED;
	}

	const char *base = strrchr(p, '/');

	base = base ? base + 1 : relative;
	if (write && (!*relative || vau_policy_core_plugin(base)))
		return VAU_POLICY_PROTECTED;

	static const char *const internal[] = {
		"ur0:data/vita-agent-use",
		"ux0:data/vita-agent-use/control",
		"ux0:data/vita-agent-use/trash",
		"ux0:data/vita-agent-use/transactions",
	};
	for (unsigned i = 0; i < sizeof(internal) / sizeof(*internal); ++i) {
		if ((under(p, internal[i]) || (destructive && under(internal[i], p))) &&
		    !(op == VAU_FS_READ && !strcmp(p, "ur0:data/vita-agent-use/runtime.log"))) {
			return VAU_POLICY_PROTECTED;
		}
	}

	if (write && which >= 0 && same(base, "config.txt") && op != VAU_FS_WRITE)
		return VAU_POLICY_PROTECTED;

	const char *risk   = which >= 0 ? tai[which] : under(p, "ur0:shell") ? "ur0:shell" : NULL;
	unsigned right     = write ? VAU_ACL_WRITE : VAU_ACL_READ;
	int granted        = !write || ((mount_is(p, "ux0") || mount_is(p, "ur0")) && !risk);
	size_t specificity = 0;
	unsigned allow = 0, deny = 0;
	int matched = 0;

	for (unsigned i = 0; i < policy->count; ++i) {
		const struct vau_acl_rule *r = &policy->rules[i];

		if (strcmp(r->subject, "*") && strcmp(r->subject, subject))
			continue;
		if (!acl_under(p, r->path))
			continue;

		/* A broad ACL may deny risky paths but cannot accidentally grant them. */
		unsigned a = r->allow;

		if (write && risk && !under(r->path, risk))
			a &= ~VAU_ACL_WRITE;
		if (!((a | r->deny) & right))
			continue;

		size_t n = strlen(r->path);

		if (!matched || n > specificity) {
			specificity = n;
			allow = deny = 0;
			matched      = 1;
		}

		if (n == specificity) {
			allow |= a;
			deny |= r->deny;
		}
	}

	if (matched)
		granted = (allow & right) && !(deny & right);
	if (!granted)
		return VAU_POLICY_READ_ONLY;
	if (write && risk && !yes)
		return VAU_POLICY_INTENT_REQUIRED;
	return VAU_POLICY_ALLOW;
}
