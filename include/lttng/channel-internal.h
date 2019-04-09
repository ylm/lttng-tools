/*
 * Copyright (C) 2015 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef LTTNG_CHANNEL_INTERNAL_H
#define LTTNG_CHANNEL_INTERNAL_H

#include <common/macros.h>

struct lttng_channel_attr_serialized {
	int overwrite;                      /* -1: session default, 1: overwrite, 0: discard */
	uint64_t subbuf_size;               /* bytes, power of 2 */
	uint64_t num_subbuf;                /* power of 2 */
	unsigned int switch_timer_interval; /* usec */
	unsigned int read_timer_interval;   /* usec */
	uint32_t output; /* enum lttng_event_output */
	/* LTTng 2.1 padding limit */
	uint64_t tracefile_size;            /* bytes */
	uint64_t tracefile_count;           /* number of tracefiles */
	/* LTTng 2.3 padding limit */
	unsigned int live_timer_interval;   /* usec */
	/* LTTng 2.7 padding limit */

} LTTNG_PACKED;

struct lttng_channel_serialized {
	char name[LTTNG_SYMBOL_NAME_LEN];
	uint32_t enabled;
	struct lttng_channel_attr_serialized attr;

} LTTNG_PACKED;

struct lttng_channel_extended {
	uint64_t discarded_events;
	uint64_t lost_packets;
	uint64_t monitor_timer_interval;
	int64_t blocking_timeout;
};

struct lttng_channel_extended_serialized {
	uint64_t discarded_events;
	uint64_t lost_packets;
	uint64_t monitor_timer_interval;
	int64_t blocking_timeout;
} LTTNG_PACKED;

int lttng_channel_serialize(struct lttng_channel_serialized *dst, const struct lttng_channel *src);
int lttng_channel_deserialize(struct lttng_channel *dst, const struct lttng_channel_serialized *src);
int lttng_channel_extended_deserialize(struct lttng_channel_extended *dst, const struct lttng_channel_extended_serialized *src);
int lttng_channel_extended_serialize(struct lttng_channel_extended_serialized *dst, const struct lttng_channel_extended *src);
int init_serialized_extended_channel(struct lttng_domain *domain, struct lttng_channel_extended_serialized *extended);
#endif /* LTTNG_CHANNEL_INTERNAL_H */
