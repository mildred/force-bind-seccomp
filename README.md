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
      -t <nsecs>            Tracer delays 'nsecs' before inspecting target
      -D                    Debug messages
      -v                    Verbose
      -q                    Quiet

Last rules (-m, -b, -d) are applied first. Rules are:

      -m ADDR/PREFIX=ADDR   Replace bind() matching first ADDR/PREFIX with
                            second ADDR (ADDR is IP:PORT)
      -b ADDR               Replace all bind() with ADDR (if same family)
      -d                    Deny all bind()

In the rules, ADDR can be:

      IP:PORT               Changes the bind target to specified address
      fd=N                  dup2() the specified inherited file descriptor
                            in place
      sd=N                  same as fd=N but for systemd file descriptor. sd=0
                            is thus equivalent to fd=3


Version: fb979de
```

Test
----

    make force-bind target-bind
    ./force-bind -v -b 127.0.0.2:16379 ./target-bind 7777
    nc -u 127.0.0.1 16379

Reference
---------

- https://github.com/emptymonkey/ptrace_do
- http://www.alfonsobeato.net/c/filter-and-modify-system-calls-with-seccomp-and-ptrace/
- http://www.alfonsobeato.net/c/modifying-system-call-arguments-with-ptrace/

- http://man7.org/tlpi/code/online/dist/seccomp/seccomp_user_notification.c
- https://news.ycombinator.com/item?id=19187417
- https://2019.linux.conf.au/schedule/presentation/236/ (Tue 22 Jan 2019)
- https://youtube.com/watch?v=sqvF_Mdtzgg
- https://github.com/Intika-Linux-Firewall/Force-Bind
- http://kernel.embedromix.ro/us/ http://kernel.embedromix.ro/us/force_bind/
