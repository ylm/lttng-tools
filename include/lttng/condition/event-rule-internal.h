/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CONDITION_EVENT_RULE_INTERNAL_H
#define LTTNG_CONDITION_EVENT_RULE_INTERNAL_H

#include <lttng/condition/condition-internal.h>
#include <common/buffer-view.h>
#include <common/macros.h>
#include <lttng/condition/evaluation-internal.h>
#include <common/dynamic-array.h>

struct lttng_capture_descriptor {
	struct lttng_event_expr *event_expression;
	struct lttng_bytecode *bytecode;
};

struct lttng_condition_event_rule {
	struct lttng_condition parent;
	struct lttng_event_rule *rule;

	/* Array of `struct lttng_capture_descriptor *`. */
	struct lttng_dynamic_pointer_array capture_descriptors;
};

struct lttng_evaluation_event_rule {
	struct lttng_evaluation parent;
	char *name;
};

struct lttng_evaluation_event_rule_comm {
	/* Includes the null terminator. */
	uint32_t trigger_name_length;
	/* Trigger name. */
	char payload[];
} LTTNG_PACKED;

LTTNG_HIDDEN
ssize_t lttng_condition_event_rule_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_condition **condition);

LTTNG_HIDDEN
enum lttng_condition_status
lttng_condition_event_rule_borrow_rule_mutable(
		const struct lttng_condition *condition,
		struct lttng_event_rule **rule);

LTTNG_HIDDEN
struct lttng_evaluation *lttng_evaluation_event_rule_create(
		const char* trigger_name);

LTTNG_HIDDEN
ssize_t lttng_evaluation_event_rule_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_evaluation **_evaluation);

LTTNG_HIDDEN
enum lttng_error_code
lttng_condition_event_rule_generate_capture_descriptor_bytecode(
		struct lttng_condition *condition);

LTTNG_HIDDEN
const struct lttng_bytecode *
lttng_condition_event_rule_get_capture_bytecode_at_index(
		const struct lttng_condition *condition, unsigned int index);

#endif /* LTTNG_CONDITION_EVENT_RULE_INTERNAL_H */
