/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_FILE_TREE_H
#define VAU_FILE_TREE_H

#include "file_ops.h"

/* Serialized native walk, bounded by path length rather than directory
 * contents. Caller chooses pre-order preflight or post-order mutation.
 * Internal paths are trusted adapter inputs, never unvalidated peer JSON. */
typedef int (*vau_tree_visit)(void *, const char *, const struct vau_file_info *);
int vau_native_tree_walk(const char *, int, vau_tree_visit, void *, int (*)(void *), void *);

#endif
