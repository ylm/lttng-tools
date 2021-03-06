# SPDX-License-Identifier: GPL-2.0-only

AUTOMAKE_OPTIONS = subdir-objects

SUBDIRS = \
	string-utils \
	bytecode \
	filter \
	argpar

# Make sure to always distribute all folders
# since SUBDIRS is decided at configure time.
DIST_SUBDIRS = \
	compat \
	health \
	hashtable \
	kernel-ctl \
	sessiond-comm \
	relayd \
	kernel-consumer \
	ust-consumer \
	testpoint \
	index \
	config \
	consumer \
	string-utils \
	fd-tracker \
	bytecode \
	filter \
	argpar

# Common library
noinst_LTLIBRARIES = libcommon.la
EXTRA_DIST = mi-lttng-4.0.xsd

libcommon_la_SOURCES = \
	actions/action.c \
	actions/group.c \
	actions/notify.c \
	actions/rotate-session.c \
	actions/snapshot-session.c \
	actions/start-session.c \
	actions/stop-session.c \
	buffer-view.h buffer-view.c \
	common.h \
	conditions/buffer-usage.c \
	conditions/condition.c \
	conditions/event-rule.c \
	conditions/session-consumed-size.c \
	conditions/session-rotation.c \
	context.c context.h \
	credentials.c credentials.h \
	daemonize.c daemonize.h \
	defaults.c \
	domain.c \
	dynamic-array.c dynamic-array.h \
	dynamic-buffer.c dynamic-buffer.h \
	endpoint.c \
	error.c error.h \
	evaluation.c \
	event.c \
	event-expr-to-bytecode.c event-expr-to-bytecode.h \
	event-field-value.c \
	event-rule/event-rule.c \
	event-rule/kprobe.c \
	event-rule/syscall.c \
	event-rule/uprobe.c \
	event-rule/tracepoint.c \
	filter.c filter.h \
	fd-handle.c fd-handle.h \
	fs-handle.c fs-handle.h fs-handle-internal.h \
	futex.c futex.h \
	kernel-probe.c \
	location.c \
	mi-lttng.c mi-lttng.h \
	notification.c \
	optional.h \
	payload.c payload.h \
	payload-view.c payload-view.h \
	pipe.c pipe.h \
	readwrite.c readwrite.h \
	runas.c runas.h \
	session-descriptor.c \
	snapshot.c snapshot.h \
	spawn-viewer.c spawn-viewer.h \
	time.c \
	trace-chunk.c trace-chunk.h \
	trace-chunk-registry.h \
	trigger.c \
	unix.c unix.h \
	uri.c uri.h \
	userspace-probe.c \
	utils.c utils.h \
	uuid.c uuid.h \
	thread.c thread.h \
	tracker.c tracker.h \
	waiter.c waiter.h

if HAVE_ELF_H
libcommon_la_SOURCES += \
	lttng-elf.c lttng-elf.h
endif

libcommon_la_LIBADD = \
	$(top_builddir)/src/common/bytecode/libbytecode.la \
	$(top_builddir)/src/common/config/libconfig.la \
	$(top_builddir)/src/common/compat/libcompat.la \
	$(top_builddir)/src/common/hashtable/libhashtable.la \
	$(top_builddir)/src/common/fd-tracker/libfd-tracker.la \
	$(top_builddir)/src/common/filter/libfilter.la \
	$(top_builddir)/src/vendor/msgpack/libmsgpack.la

if BUILD_LIB_COMPAT
SUBDIRS += compat
endif

if BUILD_LIB_HEALTH
SUBDIRS += health
endif

if BUILD_LIB_HASHTABLE
SUBDIRS += hashtable
endif

if BUILD_LIB_KERNEL_CTL
SUBDIRS += kernel-ctl
endif

if BUILD_LIB_SESSIOND_COMM
SUBDIRS += sessiond-comm
endif

if BUILD_LIB_RELAYD
SUBDIRS += relayd
endif

if BUILD_LIB_FD_TRACKER
SUBDIRS += fd-tracker
endif

if BUILD_LIB_KERNEL_CONSUMER
SUBDIRS += kernel-consumer
endif

if BUILD_LIB_UST_CONSUMER
SUBDIRS += ust-consumer
endif

if BUILD_LIB_TESTPOINT
SUBDIRS += testpoint
endif

if BUILD_LIB_INDEX
SUBDIRS += index
endif

if BUILD_LIB_CONFIG
SUBDIRS += config
endif

if BUILD_LIB_CONSUMER
SUBDIRS += consumer
endif

noinst_HEADERS = \
	align.h \
	bug.h \
	defaults.h \
	error.h \
	futex.h \
	lttng-kernel.h \
	lttng-kernel-old.h \
	macros.h \
	time.h \
	uri.h \
	utils.h

all-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
		cp -f $(srcdir)/$$script $(builddir); \
		done; \
	fi

clean-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
		rm -f $(builddir)/$$script; \
		done; \
	fi
