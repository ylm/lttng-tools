/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <endian.h>

#include <common/common.h>

#include "sessiond-comm.h"

/* For Unix socket */
#include <common/unix.h>
/* For Inet socket */
#include "inet.h"
/* For Inet6 socket */
#include "inet6.h"

#define NETWORK_TIMEOUT_ENV	"LTTNG_NETWORK_SOCKET_TIMEOUT"

static struct lttcomm_net_family net_families[] = {
	{ LTTCOMM_INET, lttcomm_create_inet_sock },
	{ LTTCOMM_INET6, lttcomm_create_inet6_sock },
};

/*
 * Human readable error message.
 */
static const char *lttcomm_readable_code[] = {
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_COMMAND_SOCK_READY) ] = "consumerd command socket ready",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_SUCCESS_RECV_FD) ] = "consumerd success on receiving fds",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_ERROR_RECV_FD) ] = "consumerd error on receiving fds",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_ERROR_RECV_CMD) ] = "consumerd error on receiving command",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_POLL_ERROR) ] = "consumerd error in polling thread",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_POLL_NVAL) ] = "consumerd polling on closed fd",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_POLL_HUP) ] = "consumerd all fd hung up",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_EXIT_SUCCESS) ] = "consumerd exiting normally",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_EXIT_FAILURE) ] = "consumerd exiting on error",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_OUTFD_ERROR) ] = "consumerd error opening the tracefile",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_SPLICE_EBADF) ] = "consumerd splice EBADF",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_SPLICE_EINVAL) ] = "consumerd splice EINVAL",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_SPLICE_ENOMEM) ] = "consumerd splice ENOMEM",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_SPLICE_ESPIPE) ] = "consumerd splice ESPIPE",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_ENOMEM) ] = "Consumer is out of memory",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_ERROR_METADATA) ] = "Error with metadata",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_FATAL) ] = "Fatal error",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_RELAYD_FAIL) ] = "Error on remote relayd",

	/* Last element */
	[ LTTCOMM_ERR_INDEX(LTTCOMM_NR) ] = "Unknown error code"
};

static unsigned long network_timeout;

int init_serialized_extended_channel(struct lttng_domain *domain, struct
		lttng_channel_extended_serialized *extended)
{
	assert(domain && extended);
	switch (domain->type) {
	case LTTNG_DOMAIN_KERNEL:
		extended->monitor_timer_interval =
			DEFAULT_KERNEL_CHANNEL_MONITOR_TIMER;
		extended->blocking_timeout =
			DEFAULT_KERNEL_CHANNEL_BLOCKING_TIMEOUT;
		break;
	case LTTNG_DOMAIN_UST:
		switch (domain->buf_type) {
		case LTTNG_BUFFER_PER_UID:
			extended->monitor_timer_interval =
				DEFAULT_UST_UID_CHANNEL_MONITOR_TIMER;
			extended->blocking_timeout =
				DEFAULT_UST_UID_CHANNEL_BLOCKING_TIMEOUT;
			break;
		case LTTNG_BUFFER_PER_PID:
		default:
			extended->monitor_timer_interval =
				DEFAULT_UST_PID_CHANNEL_MONITOR_TIMER;
			extended->blocking_timeout =
				DEFAULT_UST_PID_CHANNEL_BLOCKING_TIMEOUT;
			break;
		}
	default:
		/* Default behavior: leave set to 0. */
		break;
	}

	return 0;
}

LTTNG_HIDDEN
int lttng_channel_extended_serialize(struct lttng_channel_extended_serialized *dst,
		const struct lttng_channel_extended *src)
{
	assert(src && dst);
	dst->discarded_events = src->discarded_events;
	dst->lost_packets = src->lost_packets;
	dst->monitor_timer_interval = src->monitor_timer_interval;
	dst->blocking_timeout = src->blocking_timeout;
	return 0;
}

LTTNG_HIDDEN
int lttng_channel_extended_deserialize(struct lttng_channel_extended *dst,
		const struct lttng_channel_extended_serialized *src)
{
	assert(src && dst);
	dst->discarded_events = src->discarded_events;
	dst->lost_packets = src->lost_packets;
	dst->monitor_timer_interval = src->monitor_timer_interval;
	dst->blocking_timeout = src->blocking_timeout;
	return 0;
}

LTTNG_HIDDEN
int lttng_channel_serialize(struct lttng_channel_serialized *dst,
		const struct lttng_channel *src)
{
	assert(src && dst);
	struct lttng_channel_attr_serialized *dst_attr = &dst->attr;
	const struct lttng_channel_attr *src_attr = &src->attr;

	dst_attr->overwrite = src_attr->overwrite;
	dst_attr->subbuf_size = src_attr->subbuf_size;
	dst_attr->num_subbuf = src_attr->num_subbuf;
	dst_attr->switch_timer_interval = src_attr->switch_timer_interval;
	dst_attr->read_timer_interval = src_attr->read_timer_interval;
	dst_attr->output = (uint32_t) src_attr->output;
	dst_attr->tracefile_size = src_attr->tracefile_size;
	dst_attr->tracefile_count = src_attr->tracefile_count;
	dst_attr->live_timer_interval = src_attr->live_timer_interval;

	dst->enabled = src->enabled;
	memcpy(dst->name, src->name, sizeof(dst->name));
	return 0;
}

LTTNG_HIDDEN
int lttng_channel_deserialize(struct lttng_channel *dst,
		const struct lttng_channel_serialized *src)
{
	assert(src && dst);
	struct lttng_channel_attr *dst_attr = &dst->attr;
	const struct lttng_channel_attr_serialized *src_attr = &src->attr;

	dst_attr->overwrite = src_attr->overwrite;
	dst_attr->subbuf_size = src_attr->subbuf_size;
	dst_attr->num_subbuf = src_attr->num_subbuf;
	dst_attr->switch_timer_interval = src_attr->switch_timer_interval;
	dst_attr->read_timer_interval = src_attr->read_timer_interval;
	dst_attr->output = (enum lttng_event_output) src_attr->output;
	dst_attr->tracefile_size = src_attr->tracefile_size;
	dst_attr->tracefile_count = src_attr->tracefile_count;
	dst_attr->live_timer_interval = src_attr->live_timer_interval;

	dst->enabled = src->enabled;
	memcpy(dst->name, src->name, sizeof(dst->name));
	return 0;
}

LTTNG_HIDDEN
int sockaddr_in_serialize(struct sockaddr_in_serialized *dst,
		const struct sockaddr_in *src)
{
	assert(src && dst);
	dst->sin_family = (uint32_t) src->sin_family;
	dst->sin_port = (uint16_t) src->sin_port;
	dst->sin_addr.s_addr = src->sin_addr.s_addr;
	return 0;
}

LTTNG_HIDDEN
int sockaddr_in_deserialize(struct sockaddr_in *dst,
		const struct sockaddr_in_serialized *src)
{
	assert(src && dst);
	dst->sin_family = (sa_family_t) src->sin_family;
	dst->sin_port = (in_port_t) src->sin_port;
	dst->sin_addr.s_addr = src->sin_addr.s_addr;
	return 0;
}

LTTNG_HIDDEN
int sockaddr_in6_serialize(struct sockaddr_in6_serialized *dst,
		const struct sockaddr_in6 *src)
{
	assert(src && dst);

	dst->sin6_family = (uint32_t) src->sin6_family;
	dst->sin6_port = (uint16_t) src->sin6_port;
	dst->sin6_flowinfo = src->sin6_flowinfo;
	memcpy(&dst->sin6_addr._s6_addr, src->sin6_addr.s6_addr,
			sizeof(dst->sin6_addr._s6_addr));
	dst->sin6_scope_id = src->sin6_scope_id;
	return 0;
}

LTTNG_HIDDEN
int sockaddr_in6_deserialize(struct sockaddr_in6 *dst,
		const struct sockaddr_in6_serialized *src)
{
	assert(src && dst);

	dst->sin6_family = (sa_family_t) src->sin6_family;
	dst->sin6_port = (in_port_t) src->sin6_port;
	dst->sin6_flowinfo = src->sin6_flowinfo;
	memcpy(&dst->sin6_addr.s6_addr, src->sin6_addr._s6_addr,
	       sizeof(dst->sin6_addr.s6_addr));
	dst->sin6_scope_id = src->sin6_scope_id;
	return 0;
}

LTTNG_HIDDEN
int lttcomm_sockaddr_serialize(struct lttcomm_sockaddr_serialized *dst,
		const struct lttcomm_sockaddr *src)
{
	int ret = 0;

	assert(src && dst);

	dst->type = (uint32_t) src->type;

	switch (src->type) {
	case LTTCOMM_INET:
	{
		sockaddr_in_serialize(&dst->addr.sin,
				&src->addr.sin);
		break;
	}
	case LTTCOMM_INET6:
	{
		sockaddr_in6_serialize(&dst->addr.sin6,
				&src->addr.sin6);
		break;
	}
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

LTTNG_HIDDEN
int lttcomm_sockaddr_deserialize(struct lttcomm_sockaddr *dst,
		const struct lttcomm_sockaddr_serialized *src)
{
	int ret = 0;

	assert(src && dst);

	dst->type = (enum lttcomm_sock_domain) src->type;

	switch (dst->type) {
	case LTTCOMM_INET:
	{
		sockaddr_in_deserialize(&dst->addr.sin,
				&src->addr.sin);
		break;
	}
	case LTTCOMM_INET6:
	{
		sockaddr_in6_deserialize(&dst->addr.sin6,
				&src->addr.sin6);
		break;
	}
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

LTTNG_HIDDEN
int lttcomm_sock_serialize(struct lttcomm_sock_serialized *dst,
		const struct lttcomm_sock *src)
{
	int ret;

	assert(src && dst);

	dst->fd = src->fd;
	if (src->proto != LTTCOMM_SOCK_UDP &&
		src->proto != LTTCOMM_SOCK_TCP) {
		/* Code flow error. */
		assert(0);
	}
	dst->proto = (uint32_t) src->proto;
	ret = lttcomm_sockaddr_serialize(&dst->sockaddr, &src->sockaddr);

	return ret;
}

LTTNG_HIDDEN
int lttcomm_sock_deserialize(struct lttcomm_sock *dst,
		const struct lttcomm_sock_serialized *src)
{
	int ret;

	assert(src && dst);

	dst->fd = src->fd;
	dst->proto = (enum lttcomm_sock_proto) src->proto;
	if (dst->proto != LTTCOMM_SOCK_UDP &&
		dst->proto != LTTCOMM_SOCK_TCP) {
		ret = -EINVAL;
		goto end;
	}
	dst->ops = NULL;
	ret = lttcomm_sockaddr_deserialize(&dst->sockaddr, &src->sockaddr);

end:
	return ret;
}

LTTNG_HIDDEN
int lttcomm_relayd_sock_serialize(struct lttcomm_relayd_sock_serialized *dst,
		const struct lttcomm_relayd_sock *src)
{
	int ret;

	assert(src && dst);
	dst->major = src->major;
	dst->minor = src->minor;
	ret = lttcomm_sock_serialize(&dst->sock, &src->sock);

	return ret;
}

LTTNG_HIDDEN
int lttcomm_relayd_sock_deserialize(
		struct lttcomm_relayd_sock *dst,
		const struct lttcomm_relayd_sock_serialized *src)
{
	int ret;

	assert(src && dst);
	dst->major = src->major;
	dst->minor = src->minor;
	ret = lttcomm_sock_deserialize(&dst->sock, &src->sock);

	return ret;
}

/*
 * Return ptr to string representing a human readable error code from the
 * lttcomm_return_code enum.
 *
 * These code MUST be negative in other to treat that as an error value.
 */
LTTNG_HIDDEN
const char *lttcomm_get_readable_code(enum lttcomm_return_code code)
{
	code = -code;

	if (code < LTTCOMM_CONSUMERD_COMMAND_SOCK_READY || code > LTTCOMM_NR) {
		code = LTTCOMM_NR;
	}

	return lttcomm_readable_code[LTTCOMM_ERR_INDEX(code)];
}

/*
 * Create socket from an already allocated lttcomm socket structure and init
 * sockaddr in the lttcomm sock.
 */
LTTNG_HIDDEN
int lttcomm_create_sock(struct lttcomm_sock *sock)
{
	int ret, _sock_type, _sock_proto, domain;

	assert(sock);

	domain = sock->sockaddr.type;
	if (domain != LTTCOMM_INET && domain != LTTCOMM_INET6) {
		ERR("Create socket of unknown domain %d", domain);
		ret = -1;
		goto error;
	}

	switch (sock->proto) {
	case LTTCOMM_SOCK_UDP:
		_sock_type = SOCK_DGRAM;
		_sock_proto = IPPROTO_UDP;
		break;
	case LTTCOMM_SOCK_TCP:
		_sock_type = SOCK_STREAM;
		_sock_proto = IPPROTO_TCP;
		break;
	default:
		ret = -1;
		goto error;
	}

	ret = net_families[domain].create(sock, _sock_type, _sock_proto);
	if (ret < 0) {
		goto error;
	}

error:
	return ret;
}

/*
 * Return allocated lttcomm socket structure.
 */
LTTNG_HIDDEN
struct lttcomm_sock *lttcomm_alloc_sock(enum lttcomm_sock_proto proto)
{
	struct lttcomm_sock *sock;

	sock = zmalloc(sizeof(struct lttcomm_sock));
	if (sock == NULL) {
		PERROR("zmalloc create sock");
		goto end;
	}

	sock->proto = proto;
	sock->fd = -1;

end:
	return sock;
}

/*
 * Return an allocated lttcomm socket structure and copy src content into
 * the newly created socket.
 *
 * This is mostly useful when lttcomm_sock are passed between process where the
 * fd and ops have to be changed within the correct address space.
 */
LTTNG_HIDDEN
struct lttcomm_sock *lttcomm_alloc_copy_sock(struct lttcomm_sock *src)
{
	struct lttcomm_sock *sock;

	/* Safety net */
	assert(src);

	sock = lttcomm_alloc_sock(src->proto);
	if (sock == NULL) {
		goto alloc_error;
	}

	lttcomm_copy_sock(sock, src);

alloc_error:
	return sock;
}

/*
 * Create and copy socket from an allocated lttcomm socket structure.
 *
 * This is mostly useful when lttcomm_sock are passed between process where the
 * fd and ops have to be changed within the correct address space.
 */
LTTNG_HIDDEN
void lttcomm_copy_sock(struct lttcomm_sock *dst, struct lttcomm_sock *src)
{
	/* Safety net */
	assert(dst);
	assert(src);

	dst->proto = src->proto;
	dst->fd = src->fd;
	dst->ops = src->ops;
	/* Copy sockaddr information from original socket */
	memcpy(&dst->sockaddr, &src->sockaddr, sizeof(dst->sockaddr));
}

/*
 * Init IPv4 sockaddr structure.
 */
LTTNG_HIDDEN
int lttcomm_init_inet_sockaddr(struct lttcomm_sockaddr *sockaddr,
		const char *ip, unsigned int port)
{
	int ret;

	assert(sockaddr);
	assert(ip);
	assert(port > 0 && port <= 65535);

	memset(sockaddr, 0, sizeof(struct lttcomm_sockaddr));

	sockaddr->type = LTTCOMM_INET;
	sockaddr->addr.sin.sin_family = AF_INET;
	sockaddr->addr.sin.sin_port = htons(port);
	ret = inet_pton(sockaddr->addr.sin.sin_family, ip,
			&sockaddr->addr.sin.sin_addr);
	if (ret < 1) {
		ret = -1;
		ERR("%s with port %d: unrecognized IPv4 address", ip, port);
		goto error;
	}
	memset(sockaddr->addr.sin.sin_zero, 0, sizeof(sockaddr->addr.sin.sin_zero));

error:
	return ret;
}

/*
 * Init IPv6 sockaddr structure.
 */
LTTNG_HIDDEN
int lttcomm_init_inet6_sockaddr(struct lttcomm_sockaddr *sockaddr,
		const char *ip, unsigned int port)
{
	int ret;

	assert(sockaddr);
	assert(ip);
	assert(port > 0 && port <= 65535);

	memset(sockaddr, 0, sizeof(struct lttcomm_sockaddr));

	sockaddr->type = LTTCOMM_INET6;
	sockaddr->addr.sin6.sin6_family = AF_INET6;
	sockaddr->addr.sin6.sin6_port = htons(port);
	ret = inet_pton(sockaddr->addr.sin6.sin6_family, ip,
			&sockaddr->addr.sin6.sin6_addr);
	if (ret < 1) {
		ret = -1;
		goto error;
	}

error:
	return ret;
}

/*
 * Return allocated lttcomm socket structure from lttng URI.
 */
LTTNG_HIDDEN
struct lttcomm_sock *lttcomm_alloc_sock_from_uri(struct lttng_uri *uri)
{
	int ret;
	int _sock_proto;
	struct lttcomm_sock *sock = NULL;

	/* Safety net */
	assert(uri);

	/* Check URI protocol */
	if (uri->proto == LTTNG_TCP) {
		_sock_proto = LTTCOMM_SOCK_TCP;
	} else {
		ERR("Relayd invalid URI proto: %d", uri->proto);
		goto alloc_error;
	}

	sock = lttcomm_alloc_sock(_sock_proto);
	if (sock == NULL) {
		goto alloc_error;
	}

	/* Check destination type */
	if (uri->dtype == LTTNG_DST_IPV4) {
		ret = lttcomm_init_inet_sockaddr(&sock->sockaddr, uri->dst.ipv4,
				uri->port);
		if (ret < 0) {
			goto error;
		}
	} else if (uri->dtype == LTTNG_DST_IPV6) {
		ret = lttcomm_init_inet6_sockaddr(&sock->sockaddr, uri->dst.ipv6,
				uri->port);
		if (ret < 0) {
			goto error;
		}
	} else {
		/* Command URI is invalid */
		ERR("Relayd invalid URI dst type: %d", uri->dtype);
		goto error;
	}

	return sock;

error:
	lttcomm_destroy_sock(sock);
alloc_error:
	return NULL;
}

/*
 * Destroy and free lttcomm socket.
 */
LTTNG_HIDDEN
void lttcomm_destroy_sock(struct lttcomm_sock *sock)
{
	free(sock);
}

/*
 * Allocate and return a relayd socket object using a given URI to initialize
 * it and the major/minor version of the supported protocol.
 *
 * On error, NULL is returned.
 */
LTTNG_HIDDEN
struct lttcomm_relayd_sock *lttcomm_alloc_relayd_sock(struct lttng_uri *uri,
		uint32_t major, uint32_t minor)
{
	int ret;
	struct lttcomm_sock *tmp_sock = NULL;
	struct lttcomm_relayd_sock *rsock = NULL;

	assert(uri);

	rsock = zmalloc(sizeof(*rsock));
	if (!rsock) {
		PERROR("zmalloc relayd sock");
		goto error;
	}

	/* Allocate socket object from URI */
	tmp_sock = lttcomm_alloc_sock_from_uri(uri);
	if (tmp_sock == NULL) {
		goto error_free;
	}

	/*
	 * Create socket object which basically sets the ops according to the
	 * socket protocol.
	 */
	lttcomm_copy_sock(&rsock->sock, tmp_sock);
	/* Temporary socket pointer not needed anymore. */
	lttcomm_destroy_sock(tmp_sock);
	ret = lttcomm_create_sock(&rsock->sock);
	if (ret < 0) {
		goto error_free;
	}

	rsock->major = major;
	rsock->minor = minor;

	return rsock;

error_free:
	free(rsock);
error:
	return NULL;
}

/*
 * Set socket receiving timeout.
 */
LTTNG_HIDDEN
int lttcomm_setsockopt_rcv_timeout(int sock, unsigned int msec)
{
	int ret;
	struct timeval tv;

	tv.tv_sec = msec / 1000;
	tv.tv_usec = (msec % 1000) * 1000;

	ret = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (ret < 0) {
		PERROR("setsockopt SO_RCVTIMEO");
	}

	return ret;
}

/*
 * Set socket sending timeout.
 */
LTTNG_HIDDEN
int lttcomm_setsockopt_snd_timeout(int sock, unsigned int msec)
{
	int ret;
	struct timeval tv;

	tv.tv_sec = msec / 1000;
	tv.tv_usec = (msec % 1000) * 1000;

	ret = setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	if (ret < 0) {
		PERROR("setsockopt SO_SNDTIMEO");
	}

	return ret;
}

LTTNG_HIDDEN
int lttcomm_sock_get_port(const struct lttcomm_sock *sock, uint16_t *port)
{
	assert(sock);
	assert(port);
	assert(sock->sockaddr.type == LTTCOMM_INET ||
			sock->sockaddr.type == LTTCOMM_INET6);
	assert(sock->proto == LTTCOMM_SOCK_TCP ||
			sock->proto == LTTCOMM_SOCK_UDP);

	switch (sock->sockaddr.type) {
	case LTTCOMM_INET:
		*port = ntohs(sock->sockaddr.addr.sin.sin_port);
		break;
	case LTTCOMM_INET6:
		*port = ntohs(sock->sockaddr.addr.sin6.sin6_port);
		break;
	default:
		abort();
	}

	return 0;
}

LTTNG_HIDDEN
int lttcomm_sock_set_port(struct lttcomm_sock *sock, uint16_t port)
{
	assert(sock);
	assert(sock->sockaddr.type == LTTCOMM_INET ||
			sock->sockaddr.type == LTTCOMM_INET6);
	assert(sock->proto == LTTCOMM_SOCK_TCP ||
			sock->proto == LTTCOMM_SOCK_UDP);

	switch (sock->sockaddr.type) {
	case LTTCOMM_INET:
		sock->sockaddr.addr.sin.sin_port = htons(port);
		break;
	case LTTCOMM_INET6:
		sock->sockaddr.addr.sin6.sin6_port = htons(port);
		break;
	default:
		abort();
	}

	return 0;
}

LTTNG_HIDDEN
void lttcomm_init(void)
{
	const char *env;

	env = getenv(NETWORK_TIMEOUT_ENV);
	if (env) {
		long timeout;

		errno = 0;
		timeout = strtol(env, NULL, 0);
		if (errno != 0 || timeout < -1L) {
			PERROR("Network timeout");
		} else {
			if (timeout > 0) {
				network_timeout = timeout;
			}
		}
	}
}

LTTNG_HIDDEN
unsigned long lttcomm_get_network_timeout(void)
{
	return network_timeout;
}
