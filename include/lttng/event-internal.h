/*
 * event-internal.h
 *
 * Linux Trace Toolkit Control Library
 *
 * Copyright (C) 2017 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef LTTNG_EVENT_INTERNAL_H
#define LTTNG_EVENT_INTERNAL_H

#include <common/macros.h>
#include <lttng/event.h>

struct lttng_userspace_probe_location;

struct lttng_event_probe_attr_serialized {
	uint64_t addr;

	uint64_t offset;
	char symbol_name[LTTNG_SYMBOL_NAME_LEN];
} LTTNG_PACKED;

struct lttng_event_function_attr_serialized {
	char symbol_name[LTTNG_SYMBOL_NAME_LEN];
} LTTNG_PACKED;

struct lttng_event_serialized {
	uint32_t type; /* enum lttng_event_type */

	char name[LTTNG_SYMBOL_NAME_LEN];

	uint32_t loglevel_type; /* enum lttng_loglevel_type */

	int loglevel;

	int32_t enabled;	/* Does not apply: -1 */

	pid_t pid;

	unsigned char filter;	/* filter enabled ? */

	unsigned char exclusion; /* exclusions added ? */

	/* Event flag, from 2.6 and above. */
	uint32_t flags; /* enum lttng_event_flag */

	/* Per event type configuration */
	union {
		struct lttng_event_probe_attr_serialized probe;
		struct lttng_event_function_attr_serialized ftrace;
	} attr;
} LTTNG_PACKED;

struct lttng_event_perf_counter_ctx_serialized {
	uint32_t type;
	uint64_t config;
	char name[LTTNG_SYMBOL_NAME_LEN];
} LTTNG_PACKED;

struct lttng_event_context_serialized {
	uint32_t ctx; /* enum lttng_event_context_type */
	struct lttng_event_perf_counter_ctx_serialized perf_counter;
} LTTNG_PACKED;

struct lttng_event_extended {
	/*
	 * exclusions and filter_expression are only set when the lttng_event
	 * was created/allocated by a list operation. These two elements must
	 * not be free'd as they are part of the same contiguous buffer that
	 * contains all events returned by the listing.
	 */
	char *filter_expression;
	struct {
		unsigned int count;
		/* Array of strings of fixed LTTNG_SYMBOL_NAME_LEN length. */
		char *strings;
	} exclusions;
	struct lttng_userspace_probe_location *probe_location;
};

LTTNG_HIDDEN
struct lttng_event *lttng_event_copy(const struct lttng_event *event);

int lttng_event_probe_attr_serialize(struct lttng_event_serialized *dst, const struct lttng_event *src);
int lttng_event_function_attr_serialize(struct lttng_event_serialized *dst, const struct lttng_event *src);
int lttng_event_no_attr_serialize(struct lttng_event_serialized *dst, const struct lttng_event *src);
int lttng_event_probe_attr_deserialize(struct lttng_event *dst, const struct lttng_event_serialized *src);
int lttng_event_function_attr_deserialize(struct lttng_event *dst, const struct lttng_event_serialized *src);
int lttng_event_no_attr_deserialize(struct lttng_event *dst, const struct lttng_event_serialized *src);
int lttng_event_context_serialize(struct lttng_event_context_serialized *dst, const struct lttng_event_context *src);
int lttng_event_context_deserialize(struct lttng_event_context *dst, const struct lttng_event_context_serialized *src);
int lttng_event_perf_counter_ctx_serialize(struct lttng_event_perf_counter_ctx_serialized *dst, const struct lttng_event_perf_counter_ctx *src);
int lttng_event_perf_counter_ctx_deserialize(struct lttng_event_perf_counter_ctx *dst, const struct lttng_event_perf_counter_ctx_serialized *src);
#endif /* LTTNG_EVENT_INTERNAL_H */
