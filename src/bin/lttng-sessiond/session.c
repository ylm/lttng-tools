/*
 * Copyright (C)  2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <limits.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <urcu.h>
#include <dirent.h>
#include <sys/types.h>
#include <pthread.h>

#include <common/common.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <lttng/location-internal.h>
#include "lttng-sessiond.h"
#include "kernel.h"

#include "session.h"
#include "utils.h"
#include "trace-ust.h"
#include "timer.h"

/*
 * NOTES:
 *
 * No ltt_session.lock is taken here because those data structure are widely
 * spread across the lttng-tools code base so before caling functions below
 * that can read/write a session, the caller MUST acquire the session lock
 * using session_lock() and session_unlock().
 */

/*
 * Init tracing session list.
 *
 * Please see session.h for more explanation and correct usage of the list.
 */
static struct ltt_session_list ltt_session_list = {
	.head = CDS_LIST_HEAD_INIT(ltt_session_list.head),
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.removal_cond = PTHREAD_COND_INITIALIZER,
	.next_uuid = 0,
};

/* These characters are forbidden in a session name. Used by validate_name. */
static const char *forbidden_name_chars = "/";

/* Global hash table to keep the sessions, indexed by id. */
static struct lttng_ht *ltt_sessions_ht_by_id = NULL;

/*
 * Validate the session name for forbidden characters.
 *
 * Return 0 on success else -1 meaning a forbidden char. has been found.
 */
static int validate_name(const char *name)
{
	int ret;
	char *tok, *tmp_name;

	assert(name);

	tmp_name = strdup(name);
	if (!tmp_name) {
		/* ENOMEM here. */
		ret = -1;
		goto error;
	}

	tok = strpbrk(tmp_name, forbidden_name_chars);
	if (tok) {
		DBG("Session name %s contains a forbidden character", name);
		/* Forbidden character has been found. */
		ret = -1;
		goto error;
	}
	ret = 0;

error:
	free(tmp_name);
	return ret;
}

/*
 * Add a ltt_session structure to the global list.
 *
 * The caller MUST acquire the session list lock before.
 * Returns the unique identifier for the session.
 */
static uint64_t add_session_list(struct ltt_session *ls)
{
	assert(ls);

	cds_list_add(&ls->list, &ltt_session_list.head);
	return ltt_session_list.next_uuid++;
}

/*
 * Delete a ltt_session structure to the global list.
 *
 * The caller MUST acquire the session list lock before.
 */
static void del_session_list(struct ltt_session *ls)
{
	assert(ls);

	cds_list_del(&ls->list);
}

/*
 * Return a pointer to the session list.
 */
struct ltt_session_list *session_get_list(void)
{
	return &ltt_session_list;
}

/*
 * Returns once the session list is empty.
 */
void session_list_wait_empty(void)
{
	pthread_mutex_lock(&ltt_session_list.lock);
	while (!cds_list_empty(&ltt_session_list.head)) {
		pthread_cond_wait(&ltt_session_list.removal_cond,
				&ltt_session_list.lock);
	}
	pthread_mutex_unlock(&ltt_session_list.lock);
}

/*
 * Acquire session list lock
 */
void session_lock_list(void)
{
	pthread_mutex_lock(&ltt_session_list.lock);
}

/*
 * Try to acquire session list lock
 */
int session_trylock_list(void)
{
	return pthread_mutex_trylock(&ltt_session_list.lock);
}

/*
 * Release session list lock
 */
void session_unlock_list(void)
{
	pthread_mutex_unlock(&ltt_session_list.lock);
}

/*
 * Get the session's consumer destination type.
 *
 * The caller must hold the session lock.
 */
enum consumer_dst_type session_get_consumer_destination_type(
		const struct ltt_session *session)
{
	/*
	 * The output information is duplicated in both of those session types.
	 * Hence, it doesn't matter from which it is retrieved. However, it is
	 * possible for only one of them to be set.
	 */
	return session->kernel_session ?
			session->kernel_session->consumer->type :
			session->ust_session->consumer->type;
}

/*
 * Get the session's consumer network hostname.
 * The caller must ensure that the destination is of type "net".
 *
 * The caller must hold the session lock.
 */
const char *session_get_net_consumer_hostname(const struct ltt_session *session)
{
	const char *hostname = NULL;
	const struct consumer_output *output;

	output = session->kernel_session ?
			session->kernel_session->consumer :
			session->ust_session->consumer;

	/*
	 * hostname is assumed to be the same for both control and data
	 * connections.
	 */
	switch (output->dst.net.control.dtype) {
	case LTTNG_DST_IPV4:
		hostname = output->dst.net.control.dst.ipv4;
		break;
	case LTTNG_DST_IPV6:
		hostname = output->dst.net.control.dst.ipv6;
		break;
	default:
		abort();
	}
	return hostname;
}

/*
 * Get the session's consumer network control and data ports.
 * The caller must ensure that the destination is of type "net".
 *
 * The caller must hold the session lock.
 */
void session_get_net_consumer_ports(const struct ltt_session *session,
		uint16_t *control_port, uint16_t *data_port)
{
	const struct consumer_output *output;

	output = session->kernel_session ?
			session->kernel_session->consumer :
			session->ust_session->consumer;
	*control_port = output->dst.net.control.port;
	*data_port = output->dst.net.data.port;
}

/*
 * Get the location of the latest trace archive produced by a rotation.
 *
 * The caller must hold the session lock.
 */
struct lttng_trace_archive_location *session_get_trace_archive_location(
		struct ltt_session *session)
{
	struct lttng_trace_archive_location *location = NULL;

	if (session->rotation_state != LTTNG_ROTATION_STATE_COMPLETED) {
		goto end;
	}

	switch (session_get_consumer_destination_type(session)) {
	case CONSUMER_DST_LOCAL:
		location = lttng_trace_archive_location_local_create(
				session->rotation_chunk.current_rotate_path);
		break;
	case CONSUMER_DST_NET:
	{
		const char *hostname;
		uint16_t control_port, data_port;

		hostname = session_get_net_consumer_hostname(session);
		session_get_net_consumer_ports(session,
				&control_port,
				&data_port);
		location = lttng_trace_archive_location_relay_create(
				hostname,
				LTTNG_TRACE_ARCHIVE_LOCATION_RELAY_PROTOCOL_TYPE_TCP,
				control_port, data_port,
				session->rotation_chunk.current_rotate_path);
		break;
	}
	default:
		abort();
	}
end:
	return location;
}

/*
 * Allocate the ltt_sessions_ht_by_id HT.
 *
 * The session list lock must be held.
 */
int ltt_sessions_ht_alloc(void)
{
	int ret = 0;

	DBG("Allocating ltt_sessions_ht_by_id");
	ltt_sessions_ht_by_id = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!ltt_sessions_ht_by_id) {
		ret = -1;
		ERR("Failed to allocate ltt_sessions_ht_by_id");
		goto end;
	}
end:
	return ret;
}

/*
 * Destroy the ltt_sessions_ht_by_id HT.
 *
 * The session list lock must be held.
 */
static void ltt_sessions_ht_destroy(void)
{
	if (!ltt_sessions_ht_by_id) {
		return;
	}
	ht_cleanup_push(ltt_sessions_ht_by_id);
	ltt_sessions_ht_by_id = NULL;
}

/*
 * Add a ltt_session to the ltt_sessions_ht_by_id.
 * If unallocated, the ltt_sessions_ht_by_id HT is allocated.
 * The session list lock must be held.
 */
static void add_session_ht(struct ltt_session *ls)
{
	int ret;

	assert(ls);

	if (!ltt_sessions_ht_by_id) {
		ret = ltt_sessions_ht_alloc();
		if (ret) {
			ERR("Error allocating the sessions HT");
			goto end;
		}
	}
	lttng_ht_node_init_u64(&ls->node, ls->id);
	lttng_ht_add_unique_u64(ltt_sessions_ht_by_id, &ls->node);

end:
	return;
}

/*
 * Test if ltt_sessions_ht_by_id is empty.
 * Return 1 if empty, 0 if not empty.
 * The session list lock must be held.
 */
static int ltt_sessions_ht_empty(void)
{
	int ret;

	if (!ltt_sessions_ht_by_id) {
		ret = 1;
		goto end;
	}

	ret = lttng_ht_get_count(ltt_sessions_ht_by_id) ? 0 : 1;
end:
	return ret;
}

/*
 * Remove a ltt_session from the ltt_sessions_ht_by_id.
 * If empty, the ltt_sessions_ht_by_id HT is freed.
 * The session list lock must be held.
 */
static void del_session_ht(struct ltt_session *ls)
{
	struct lttng_ht_iter iter;
	int ret;

	assert(ls);
	assert(ltt_sessions_ht_by_id);

	iter.iter.node = &ls->node.node;
	ret = lttng_ht_del(ltt_sessions_ht_by_id, &iter);
	assert(!ret);

	if (ltt_sessions_ht_empty()) {
		DBG("Empty ltt_sessions_ht_by_id, destroying it");
		ltt_sessions_ht_destroy();
	}
}

/*
 * Acquire session lock
 */
void session_lock(struct ltt_session *session)
{
	assert(session);

	pthread_mutex_lock(&session->lock);
}

/*
 * Release session lock
 */
void session_unlock(struct ltt_session *session)
{
	assert(session);

	pthread_mutex_unlock(&session->lock);
}

static
void session_release(struct urcu_ref *ref)
{
	int ret;
	struct ltt_ust_session *usess;
	struct ltt_kernel_session *ksess;
	struct ltt_session *session = container_of(ref, typeof(*session), ref);

	usess = session->ust_session;
	ksess = session->kernel_session;

	/* Clean kernel session teardown */
	kernel_destroy_session(ksess);

	/* UST session teardown */
	if (usess) {
		/* Close any relayd session */
		consumer_output_send_destroy_relayd(usess->consumer);

		/* Destroy every UST application related to this session. */
		ret = ust_app_destroy_trace_all(usess);
		if (ret) {
			ERR("Error in ust_app_destroy_trace_all");
		}

		/* Clean up the rest. */
		trace_ust_destroy_session(usess);
	}

	/*
	 * Must notify the kernel thread here to update it's poll set in order to
	 * remove the channel(s)' fd just destroyed.
	 */
	ret = notify_thread_pipe(kernel_poll_pipe[1]);
	if (ret < 0) {
		PERROR("write kernel poll pipe");
	}

	DBG("Destroying session %s (id %" PRIu64 ")", session->name, session->id);
	pthread_mutex_destroy(&session->lock);

	consumer_output_put(session->consumer);
	snapshot_destroy(&session->snapshot);

	ASSERT_LOCKED(ltt_session_list.lock);
	del_session_list(session);
	del_session_ht(session);
	pthread_cond_broadcast(&ltt_session_list.removal_cond);
	free(session);
}

/*
 * Acquire a reference to a session.
 * This function may fail (return false); its return value must be checked.
 */
bool session_get(struct ltt_session *session)
{
	return urcu_ref_get_unless_zero(&session->ref);
}

/*
 * Release a reference to a session.
 */
void session_put(struct ltt_session *session)
{
	/*
	 * The session list lock must be held as any session_put()
	 * may cause the removal of the session from the session_list.
	 */
	ASSERT_LOCKED(ltt_session_list.lock);
	assert(session->ref.refcount);
	urcu_ref_put(&session->ref, session_release);
}

/*
 * Destroy a session.
 *
 * This method does not immediately release/free the session as other
 * components may still hold a reference to the session. However,
 * the session should no longer be presented to the user.
 *
 * Releases the session list's reference to the session
 * and marks it as destroyed. Iterations on the session list should be
 * mindful of the "destroyed" flag.
 */
void session_destroy(struct ltt_session *session)
{
	assert(!session->destroyed);
	session->destroyed = true;
	session_put(session);
}

/*
 * Return a ltt_session structure ptr that matches name. If no session found,
 * NULL is returned. This must be called with the session list lock held using
 * session_lock_list and session_unlock_list.
 * A reference to the session is implicitly acquired by this function.
 */
struct ltt_session *session_find_by_name(const char *name)
{
	struct ltt_session *iter;

	assert(name);
	ASSERT_LOCKED(ltt_session_list.lock);

	DBG2("Trying to find session by name %s", name);

	cds_list_for_each_entry(iter, &ltt_session_list.head, list) {
		//FIXME: ylamarre: name might also not be NULL terminated and less than NAME_MAX
		if (!strncmp(iter->name, name, NAME_MAX) &&
				!iter->destroyed) {
			goto found;
		}
	}

	return NULL;
found:
	return session_get(iter) ? iter : NULL;
}

/*
 * Return an ltt_session that matches the id. If no session is found,
 * NULL is returned. This must be called with rcu_read_lock and
 * session list lock held (to guarantee the lifetime of the session).
 */
struct ltt_session *session_find_by_id(uint64_t id)
{
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;
	struct ltt_session *ls;

	ASSERT_LOCKED(ltt_session_list.lock);

	if (!ltt_sessions_ht_by_id) {
		goto end;
	}

	lttng_ht_lookup(ltt_sessions_ht_by_id, &id, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if (node == NULL) {
		goto end;
	}
	ls = caa_container_of(node, struct ltt_session, node);

	DBG3("Session %" PRIu64 " found by id.", id);
	return session_get(ls) ? ls : NULL;

end:
	DBG3("Session %" PRIu64 " NOT found by id", id);
	return NULL;
}

/*
 * Create a brand new session and add it to the session list.
 */
int session_create(char *name, uid_t uid, gid_t gid)
{
	int ret;
	struct ltt_session *new_session;

	/* Allocate session data structure */
	new_session = zmalloc(sizeof(struct ltt_session));
	if (new_session == NULL) {
		PERROR("zmalloc");
		ret = LTTNG_ERR_FATAL;
		goto error_malloc;
	}

	urcu_ref_init(&new_session->ref);

	/* Define session name */
	if (name != NULL) {
		if (snprintf(new_session->name, NAME_MAX, "%s", name) < 0) {
			ret = LTTNG_ERR_FATAL;
			goto error_asprintf;
		}
	} else {
		ERR("No session name given");
		ret = LTTNG_ERR_FATAL;
		goto error;
	}

	ret = validate_name(name);
	if (ret < 0) {
		ret = LTTNG_ERR_SESSION_INVALID_CHAR;
		goto error;
	}

	ret = gethostname(new_session->hostname, sizeof(new_session->hostname));
	if (ret < 0) {
		if (errno == ENAMETOOLONG) {
			new_session->hostname[sizeof(new_session->hostname) - 1] = '\0';
		} else {
			ret = LTTNG_ERR_FATAL;
			goto error;
		}
	}

	/* Init kernel session */
	new_session->kernel_session = NULL;
	new_session->ust_session = NULL;

	/* Init lock */
	pthread_mutex_init(&new_session->lock, NULL);

	new_session->uid = uid;
	new_session->gid = gid;

	ret = snapshot_init(&new_session->snapshot);
	if (ret < 0) {
		ret = LTTNG_ERR_NOMEM;
		goto error;
	}

	new_session->rotation_pending_local = false;
	new_session->rotation_pending_relay = false;
	new_session->rotation_state = LTTNG_ROTATION_STATE_NO_ROTATION;

	new_session->rotation_pending_check_timer_enabled = false;
	new_session->rotation_schedule_timer_enabled = false;

	/* Add new session to the session list */
	session_lock_list();
	new_session->id = add_session_list(new_session);
	/*
	 * Add the new session to the ltt_sessions_ht_by_id.
	 * No ownership is taken by the hash table; it is merely
	 * a wrapper around the session list used for faster access
	 * by session id.
	 */
	add_session_ht(new_session);
	session_unlock_list();

	/*
	 * Consumer is let to NULL since the create_session_uri command will set it
	 * up and, if valid, assign it to the session.
	 */
	DBG("Tracing session %s created with ID %" PRIu64 " by UID %d GID %d",
			name, new_session->id, new_session->uid, new_session->gid);

	return LTTNG_OK;

error:
error_asprintf:
	free(new_session);

error_malloc:
	return ret;
}

/*
 * Check if the UID or GID match the session. Root user has access to all
 * sessions.
 */
int session_access_ok(struct ltt_session *session, uid_t uid, gid_t gid)
{
	assert(session);

	if (uid != session->uid && gid != session->gid && uid != 0) {
		return 0;
	} else {
		return 1;
	}
}

/*
 * Set a session's rotation state and reset all associated state.
 *
 * This function resets the rotation state (check timers, pending
 * flags, etc.) and sets the result of the last rotation. The result
 * can be queries by a liblttng-ctl client.
 *
 * Be careful of the result passed to this function. For instance,
 * on failure to launch a rotation, a client will expect the rotation
 * state to be set to "NO_ROTATION". If an error occured while the
 * rotation was "ONGOING", result should be set to "ERROR", which will
 * allow a client to report it.
 *
 * Must be called with the session and session_list locks held.
 */
int session_reset_rotation_state(struct ltt_session *session,
		enum lttng_rotation_state result)
{
	int ret = 0;

	ASSERT_LOCKED(ltt_session_list.lock);
	ASSERT_LOCKED(session->lock);

	session->rotation_pending_local = false;
	session->rotation_pending_relay = false;
	session->rotated_after_last_stop = false;
	session->rotation_state = result;
	if (session->rotation_pending_check_timer_enabled) {
		ret = timer_session_rotation_pending_check_stop(session);
	}
	return ret;
}
