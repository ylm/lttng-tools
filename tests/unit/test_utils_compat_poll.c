/*
 * test_notification.c
 *
 * Unit tests for the notification API.
 *
 * Copyright (C) 2019 Yannick Lamarre <ylamarre@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <tap/tap.h>

#include <common/compat/poll.h>

/* For error.h */
int lttng_opt_quiet = 1;
int lttng_opt_verbose;
int lttng_opt_mi;

#ifdef HAVE_EPOLL
#define NUM_TESTS 13
#else
#define NUM_TEST 7
#endif

#if 0
Functions to test...
#define LTTNG_POLL_GETFD(e, i) LTTNG_REF(e)->events[i].data.fd
#define LTTNG_POLL_GETEV(e, i) LTTNG_REF(e)->events[i].events
#define LTTNG_POLL_GETNB(e) LTTNG_REF(e)->nb_fd
#define LTTNG_POLL_GETSZ(e) LTTNG_REF(e)->events_size
#define LTTNG_POLL_GET_PREV_FD(e, i, nb_fd) \
lttng_poll_create();
lttng_poll_wait();
lttng_poll_add();
lttng_poll_del();
lttng_poll_mod();
lttng_poll_clean();

lttng_poll_reset();
lttng_poll_init();
#endif

#ifdef HAVE_EPOLL
#if defined(HAVE_EPOLL_CREATE1) && defined(EPOLL_CLOEXEC)
#define CLOE_VALUE EPOLL_CLOEXEC
#else
#define CLOE_VALUE FD_CLOEXEC
#endif
void test_epoll_compat()
{
	ok(LTTNG_CLOEXEC == CLOE_VALUE, "epoll's CLOEXEC value");
}
#endif

void test_alloc()
{
	struct lttng_poll_event poll_events;
	// Null pointer
	ok(lttng_poll_create(NULL, 1, NULL), "Create over NULL pointer");
	// Size 0
	ok(lttng_poll_create(&poll_events, 0, NULL), "Create with size 0");
#if 0
	// with CLOEXEC
	lttng_poll_create(&poll_events, 1, LTTNG_CLOEXEC);
	lttng_poll_clean(&poll_events);
#endif
	// without CLOEXEC
	lttng_poll_create(&poll_events, 1, NULL);
	lttng_poll_clean(&poll_events);
}

/* Tests stuff related to what would be handled with epoll_ctl. */
void test_poll_ctl()
{
	struct lttng_poll_event poll_events;
	//Test add
	ok(lttng_poll_add(NULL, 1, LPOLLIN), "Adding to NULL set");
	ok(lttng_poll_add(&poll_events, 1, LPOLLIN), "Adding to uninitialized structure");
	ok(lttng_poll_add(&poll_events, -1, LPOLLIN), "Adding invalid FD");

	lttng_poll_create(&poll_events, 1, NULL);
	ok(LTTNG_POLL_GETNB(&poll_events) == 0, "Set created empty");
	ok(lttng_poll_add(NULL, 1, LPOLLIN), "Adding to NULL set");
	ok(lttng_poll_add(&poll_events, -1, LPOLLIN), "Adding invalid FD");
	ok(LTTNG_POLL_GETNB(&poll_events) == 0, "Set created empty");

	ok(!lttng_poll_add(&poll_events, 1, LPOLLIN), "Adding valid FD");
	
	ok(LTTNG_POLL_GETNB(&poll_events) == 1, "Set created empty");
#if 0
	ok(LTTNG_POLL_GETSZ(&poll_events) == 1, "Get proper size");
#endif
	
	lttng_poll_clean(&poll_events);
}

int main(int argc, const char *argv[])
{
	plan_tests(NUM_TESTS);
#ifdef HAVE_EPOLL
	test_epoll_compat();
#endif
	test_alloc();
	test_poll_ctl();
	return exit_status();
}
