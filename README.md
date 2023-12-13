force-bind-seccomp
==================

Use seccomp to foce processes to bind to specific address instead of binding to
`0.0.0.0` (IPv4) or `[::]` (IPv6). It can also transform a process that does not
make use of systemd socket activation to use passed file descriptor instead of
binding their own sockets.

Under the hood, it works in two ways:

- if systemd socket activation is not needed, then it uses seccomp only. When a
  bind system call is detected, the process is stopped and if the bind address
  matches a force-bind rule, then the process memory is altered to replace the
  address given to `bind()` with a replacement address.

  It uses `SECCOMP_RET_USER_NOTIF` which is only available on recent kernels.

- if systemd socket activation is needed, then it uses seccomp in combinaison
  with ptrace and when a `bind()` system call is detected, then the process is
  stopped and ptrace is used to alter the process. The system call registers are
  dumped and if the address bound matches a pattern:

    - either ptrace is used to replace the address with a replacement address,
      just like with seccomp, and the bind system call continues

    - if systemd socket activation is needed for that pattern, then the system
      call is replaced by the `dup2()` system call and the return value is
      altered to return `0` in case of success.

In the future, when `SECCOMP_NOTIFY_IOCTL_ADDFD` will become available, then
ptrace could be entirely replaced by seccomp, including when systemd socket
activation is needed.

This is still a young project. Don't hesitate to report bugs or submit fixes.

Known bugs
----------

- ptrace can mess up and can make syscalls return -ENOSYS (no implemented)
- parent process always exits with status 0 in seccomp-only mode (seccomp daemon
  should pass exit status to parent process)
- if the process close a systemd activated socket and opens a new socket on the
  same file descriptor number that is not catched by force-bind, then the
  subsequent listen() calls will be skipped
- security issue: race condition when replacing the network address causing a
  malicious program to bind an otherwise forbidden address. Can be solved with
  pidfd_getfd.
- When the file descriptors are not passed by systemd (the service is started
  while the socket was not active for example), force-bind should let the
  process bind() and listen() normally

TODO:

- Use pidfd_getfd to implement bind properly on the seccomp agent side instead
  of patching memory of the target process.
- Allow to bind to hostnames which can resolve to multiple IP addresses which is
  made possible by pidfd_getfd. `getaddrinfo2()` results should be checked for a
  next address in `res->ai_next`.
- Allot to block a find matching a specific address.

History
-------

This project was bord out of dissatisfaction on how linux containers (docker or
podman) handled IPv6. I came to the conclusion that to work properly, the
containers needed to use the same network namespaces as the host, and they
should use the public address for communication with the Internet, and bind
their services on a private address space (127.0.0.0/8 on IPv4, ULA prefix on
IPv6) for container intercommunication.

I needed a way to force containers to bind services on those private addresses
while still being able to access the public addresses to connect to the
Internet. That's how `force-bind` was born.

I used a seccomp example from Michael Kerrisk written 2019 as a starting point
because I needed something that worked with `SECCOMP_RET_USER_NOTIF` which was
quite bleeding-edge at that time. Not much documentation was available. That's
the reason behind the GPLv3 license (that and the fact that I pretty much agree
with the FSF philosophy).

Next, I needed a way to force services (this time not in containers) that didn't
play well with systemd socket activation to use the socket file descriptor
passed by systemd and new options to `force-bind` were developed. Using proxies
didn't work well because you lose the source address in the process. Also, as
another indirection layer, it participates to system bloat.

Usage
-----

```
Usage: ./force-bind [options] TARGET_PROGRAM [ARGS ...]
Options
    -h                    Help
    -V                    Version information
    -m MATCH=ADDR         Replace bind() matching first MATCH with ADDR
    -b ADDR               Replace all bind() with ADDR (if same family)
    -d                    Deny all bind()
    -p                    Force seccomp-ptrace instead of only seccomp
    -D                    Debug messages
    -v                    Verbose
    -q                    Quiet

Last rules (-m, -b, -d) are applied first so you can put your general policy
first on your command-line and any following argument can override it.

With the -m rule, MATCH pattern can be:

    :PORT                 Matches both IPv4 and IPv6 listening on PORT
    ADDR:PORT/PREFIX      Matches address with given port with the netmark
                          corresponding to PREFIX applied first on both IPs
                          IPv6 address must be enclosed in squared brackets.

In the rules, ADDR can be:

    IP:PORT               Changes the bind target to specified address
    fd=N or fd-N          dup2() the specified inherited file descriptor
                          in place
    sd=N or sd-N          same as fd=N but for systemd file descriptor. sd=0
                          is thus equivalent to fd=3

Examples:

  * force-bind -m 0.0.0.0:80/0=127.0.0.1:8080 progname args...

    Replace binds from any IPv4 address port 80 to localhost-only port
    8080. IPv6 binds are allowed.

  * force-bind -d -m '[::]:80/0=[::1]:8080' progname args...

    Replace binds from any IPv6 address port 80 to localhost-only port
    8080. IPv4 binds are denied.

  * force-bind -d -b '[::1]:8081' -b '127.0.0.1:8080' progname args...

    Replace binds from any IPv6 address to localhost port 8081 and from
    any IPv4 address to localhost port 8080.

  * force-bind -m ':80=sd=0' -m ':80=fd=4' progname args...

    Replace any bind to port 80 using first socket from systemd socket
    activation. Any port 81 is replaced by passed file descriptor 4.


Version: v0.0.0-19-g2207165-dirty
```

Test
----

    make force-bind target-bind parent-socket-activate
    ./force-bind -v -b 127.0.0.1:16379 ./target-bind 7777
    nc -u 127.0.0.1 16379

    ./parent-socket-activate 127.0.0.1 8888 ./force-bind -v -b 0.0.0.0:16379/0=sd=0 ./target-bind 7777
    nc -u 127.0.0.1 8888


Requirements
------------

- [Linux 5.0](https://man7.org/tlpi/api_changes/index.html#Linux-5.0) (2019-03-03) for SECCOMP_RET_USER_NOTIF
- [Linux 5.6](https://man7.org/tlpi/api_changes/index.html#Linux-5.6) (2020-03-29) for pidfd_getfd (not used yet here, can be used to replace ptrace)
- [Linux 5.9](https://man7.org/tlpi/api_changes/index.html#Linux-5.9) (2020-10-11) for SECCOMP_IOCTL_NOTIF_ADDFD (not used yet here, can be used to correctly install systemd socket activation file descriptors)
- Linux 5.10 for BPF sk_lokup

Reference
---------

In random order:

- https://www.kernel.org/doc/html/latest/bpf/prog_sk_lookup.html
- https://blog.cloudflare.com/its-crowded-in-here/
- https://man7.org/tlpi/api_changes/index.html
- https://people.kernel.org/brauner/the-seccomp-notifier-new-frontiers-in-unprivileged-container-development
- https://nullprogram.com/blog/2018/06/23/
- https://github.com/alfonsosanchezbeato/ptrace-redirect
- https://github.com/emptymonkey/ptrace_do
- http://www.alfonsobeato.net/c/filter-and-modify-system-calls-with-seccomp-and-ptrace/
- http://www.alfonsobeato.net/c/modifying-system-call-arguments-with-ptrace/
- http://man7.org/tlpi/code/online/dist/seccomp/seccomp_user_notification.c
- https://news.ycombinator.com/item?id=19187417
- https://2019.linux.conf.au/schedule/presentation/236/ (Tue 22 Jan 2019)
- https://youtube.com/watch?v=sqvF_Mdtzgg
- https://github.com/Intika-Linux-Firewall/Force-Bind
- http://kernel.embedromix.ro/us/ http://kernel.embedromix.ro/us/force_bind/

[x86_64 syscall registers](http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/) ([and how to use it](https://stackoverflow.com/questions/33431994/extracting-system-call-name-and-arguments-using-ptrace):

- regs.rdi - Stores the first argument
- regs.rsi - Stores the second argument
- regs.rdx - Stores the third argument
- regs.r10 - Stores the fourth argument
- regs.r8 - Stores the fifth argument
- regs.r9 - Stores the sixth argument

