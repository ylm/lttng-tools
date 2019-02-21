lttng create ylm
lttng enable-channel --monitor-timer=100000 -u ylm_channel
lttng enable-event -u -a -c ylm_channel
lttng start

