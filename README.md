force-bind-seccomp
==================

Use seccomp to foce processes to bind to specific address instead of binding to
`0.0.0.0` (IPv4) or `::` (IPv6).

This is still a work in progress and is not (yet?) meant to securely enforce the
bind policy.

Reference
---------

- http://man7.org/tlpi/code/online/dist/seccomp/seccomp_user_notification.c
- https://news.ycombinator.com/item?id=19187417
- https://2019.linux.conf.au/schedule/presentation/236/ (Tue 22 Jan 2019)
- https://youtube.com/watch?v=sqvF_Mdtzgg
- https://github.com/Intika-Linux-Firewall/Force-Bind
- http://kernel.embedromix.ro/us/ http://kernel.embedromix.ro/us/force_bind/
