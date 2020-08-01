force-bind-seccomp
==================

Use seccomp to foce processes to bind to specific address instead of binding to
`0.0.0.0` (IPv4) or `::` (IPv6).

This is still a work in progress and is not (yet?) meant to securely enforce the
bind policy.

Usage
-----

```
Usage: ./force-bind [options] TARGET_PROGRAM [ARGS ...]
      Options
      -h                    Help
      -V                    Version information
      -m ADDR/PREFIX=ADDR   Replace bind() matching first ADDR/PREFIX with
                      second ADDR (ADDR is IP:PORT)
      -b ADDR               Replace all bind() with ADDR (if same family)
      -d                    Deny all bind()
      -t <nsecs>            Tracer delays 'nsecs' before inspecting target
      -D                    Debug messages
      -v                    Verbose
      -q                    Quiet

Last rules (-m, -b, -d) are applied first.

Version: fb979de
```

Reference
---------

- https://github.com/emptymonkey/ptrace_do
- http://www.alfonsobeato.net/c/filter-and-modify-system-calls-with-seccomp-and-ptrace/

- http://man7.org/tlpi/code/online/dist/seccomp/seccomp_user_notification.c
- https://news.ycombinator.com/item?id=19187417
- https://2019.linux.conf.au/schedule/presentation/236/ (Tue 22 Jan 2019)
- https://youtube.com/watch?v=sqvF_Mdtzgg
- https://github.com/Intika-Linux-Firewall/Force-Bind
- http://kernel.embedromix.ro/us/ http://kernel.embedromix.ro/us/force_bind/
