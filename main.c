/*************************************************************************\
*                  Copyright (C) Michael Kerrisk, 2019.                   *
*                                                                         *
* This program is free software. You may use, modify, and redistribute it *
* under the terms of the GNU General Public License as published by the   *
* Free Software Foundation, either version 3 or (at your option) any      *
* later version. This program is distributed without any warranty.  See   *
* the file COPYING.gpl-v3 for details.                                    *
\*************************************************************************/

/* seccomp_user_notification.c

   Demonstrate the seccomp notification-to-user-space feature added in
   Linux 5.0.

   This program creates two child processes, the "target" and the "tracer".

   The target process uses seccomp(2) to install a BPF filter using the
   SECCOMP_FILTER_FLAG_NEW_LISTENER flag. This flag causes seccomp(2) to return
   a file descriptor that can be used to receive notifications when the filter
   performs a return with the action SECCOMP_RET_USER_NOTIF; the BPF filter
   employed in this example performs such a return when the target process
   calls mkdir(2).

   The target process passes the notification file descriptor returned by
   seccomp(2) to the tracer process via a UNIX domain socket.

   The target process then performs a series of mkdir(2) calls using the
   pathnames supplied as command-line arguments to the program. The effect
   of each SECCOMP_RET_USER_NOTIF action triggered by these system calls is:

   (a) the mkdir(2) system call in the target process is *not* executed;
   (b) a notification is generated on the notification file descriptor;
   (c) the target process remains blocked in the mkdir(2) system call until
       a response is sent on the notification file descriptor (this response
       will include information for a "faked" return value for the mkdir(2)
       call--either a success return value, or a -1 error return with a value
       to be assigned to 'errno').

   The tracer process receives the notification file descriptor that was sent
   by the target process over the UNIX domain socket. It then waits for
   notifications using the SECCOMP_IOCTL_NOTIF_RECV ioctl(2) operation. Each
   of these notifications returns a structure that includes the PID of the
   target process, and information (the same 'struct seccomp_data' that a
   seccomp BPF filter receives) describing the target process's system call.
   In this example program, these notifications will relate to the mkdir(2)
   calls made by the target process.

   From user space, the tracer is able to do some things that an in-kernel
   seccomp BPF filter can't do; in particular, it can inspect the target
   process's memory (via /proc/PID/mem) in order to find out the values
   referred to by pointer arguments (e.g., the pathname argument of mkdir(2)).
   The tracer then makes a decision based on the pathname, creating the
   specified directory on behalf of the target process only if the pathname
   starts with ("/tmp/").

   The tracer then performs a SECCOMP_IOCTL_NOTIF_SEND ioctl(2) operation,
   which provides a response for the target process's system call. This
   response can specify either a success return value for the system call, or
   an error return, including a value that will be placed in 'errno' in the
   target process.
*/
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <sys/wait.h>
#include <stddef.h>
#include <stdbool.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "scm_functions.h"

#include "ip_funcs.h"

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)

static int
seccomp(unsigned int operation, unsigned int flags, void *args)
{
    return syscall(__NR_seccomp, operation, flags, args);
}

/* Values from command-line options */

struct mapping;

struct mapping {
    struct sockaddr *addr;
    int prefix;
    struct sockaddr *replacement;
    int replacement_fd;
    struct mapping *next;
};

struct cmdLineOpts {
    bool require_ptrace;
    bool debug;
    bool quiet;
    bool verbose;
    struct mapping *map;
};

static int matchAllAddr(const struct mapping *map, struct sockaddr *sa, int *newfd, const struct cmdLineOpts *opts);

/* The following is the x86-64-specific BPF boilerplate code for checking that
   the BPF program is running on the right architecture + ABI. At completion
   of these instructions, the accumulator contains the system call number. */

/* For the x32 ABI, all system call numbers have bit 30 set */

#define X32_SYSCALL_BIT         0x40000000

#define X86_64_CHECK_ARCH_AND_LOAD_SYSCALL_NR \
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, \
                (offsetof(struct seccomp_data, arch))), \
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 2), \
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, \
                 (offsetof(struct seccomp_data, nr))), \
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1), \
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)

/* installNotifyFilter() installs a seccomp filter that generates user-space
   notifications (SECCOMP_RET_USER_NOTIF) when the process calls mkdir(2); the
   filter allows all other system calls.

   The function return value is a file descriptor from which the user-space
   notifications can be fetched. */

static int
installNotifyFilter(void)
{
    struct sock_filter filter[] = {
        X86_64_CHECK_ARCH_AND_LOAD_SYSCALL_NR,

        /* bind() triggers notification to user-space tracer */

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_bind, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_USER_NOTIF),

        /* Every other system call is allowed */

        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    int notifyFd;

    /* Install the filter with the SECCOMP_FILTER_FLAG_NEW_LISTENER flag; as
       a result, seccomp() returns a notification file descriptor. */

    notifyFd = seccomp(SECCOMP_SET_MODE_FILTER,
                        SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (notifyFd == -1)
        errExit("seccomp-install-notify-filter");

    return notifyFd;
}

static void
installPtraceFilter(void)
{
    struct sock_filter filter[] = {
        X86_64_CHECK_ARCH_AND_LOAD_SYSCALL_NR,

        /* bind() triggers notification to user-space tracer */

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_bind, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRACE),

        /* Every other system call is allowed */

        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    ptrace(PTRACE_TRACEME, 0, 0, 0);

    /* To avoid the need for CAP_SYS_ADMIN */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        errExit("prctl(PR_SET_NO_NEW_PRIVS)");
    }

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
        errExit("when setting seccomp filter");
    }
}

/* Handler for the SIGINT signal in the target process */

static void
handler(int sig)
{
    /* UNSAFE: This handler uses non-async-signal-safe functions
       (printf(); see TLPI Section 21.1.2) */

    printf("Target process: received signal\n");
}

/* Close a pair of sockets created by socketpair() */

static void
closeSocketPair(int sockPair[2])
{
    if (close(sockPair[0]) == -1)
        errExit("closeSocketPair-close-0");
    if (close(sockPair[1]) == -1)
        errExit("closeSocketPair-close-1");
}

/* Implementation of the target process; create a child process that:

   (1) installs a seccomp filter with the SECCOMP_FILTER_FLAG_NEW_LISTENER
       flag;
   (2) writes the seccomp notification file descriptor returned from the
       previous step onto the UNIX domain socket, 'sockPair[0]';
   (3) exec into the designated process.

   The function return value is the PID of the child process. */

static pid_t
targetProcess(int sockPair[2], char *argv[], struct cmdLineOpts *opts)
{
    pid_t targetPid;
    int notifyFd = 0;
    struct sigaction sa;

    targetPid = fork();
    if (targetPid == -1)
        errExit("fork");

    if (targetPid > 0)          /* In parent, return PID of child */
        return targetPid;

    /* Child falls through to here */

    if(opts->debug) printf("Target process: PID = %ld\n", (long) getpid());

    /* Install a handler for the SIGINT signal */

    sa.sa_handler = handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) == -1)
        errExit("sigaction");

    /* Install seccomp filter(s) */

    if(opts->require_ptrace) {
        installPtraceFilter();

        /* Signal the tracing process we are ready
         * http://www.alfonsobeato.net/c/filter-and-modify-system-calls-with-seccomp-and-ptrace/
         * http://www.alfonsobeato.net/c/modifying-system-call-arguments-with-ptrace/
         */
        kill(getpid(), SIGSTOP);
    } else {
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
            errExit("prctl");

        notifyFd = installNotifyFilter();

        /* Pass the notification file descriptor to the tracing process over
           a UNIX domain socket */

        if (sendfd(sockPair[0], notifyFd) == -1)
            errExit("sendfd");

        /* Notification and socket FDs are no longer needed in target process */

        if (close(notifyFd) == -1)
            errExit("close-target-notify-fd");

        closeSocketPair(sockPair);
    }

    /* Exec into the designated process */

    if(execvp(argv[0], argv) == -1)
        errExit("execvp");
    exit(EXIT_FAILURE);
}

/* Check that the notification ID provided by a SECCOMP_IOCTL_NOTIF_RECV
   operation is still valid. It will no longer be valid if the process has
   terminated. This operation can be used when accessing /proc/PID files in
   the target process in order to avoid TOCTOU race conditions where the
   PID that is returned by SECCOMP_IOCTL_NOTIF_RECV terminates and is
   reused by another process. */

static void
checkNotificationIdIsValid(int notifyFd, __u64 id, char *tag, struct cmdLineOpts *opts)
{
    if (ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == -1) {
        if(opts->debug) fprintf(stderr, "Tracer: notification ID check (%s): "
                "target has died!!!!!!!!!!!\n", tag);
    }
}

/* Handle notifications that arrive via SECCOMP_RET_USER_NOTIF file
   descriptor, 'notifyFd'. */

static void
watchForNotifications(int notifyFd, struct cmdLineOpts *opts)
{
    struct seccomp_notif *req;
    struct seccomp_notif_resp *resp;
    struct seccomp_notif_sizes sizes;
    socklen_t addrlen;
    struct sockaddr *addr;
    char path[PATH_MAX];
    int procMem;        /* FD for /proc/PID/mem of target process */

    /* Discover the sizes of the structures that are used to receive
       notifications and send notification responses, and allocate
       buffers of those sizes. */

    if (seccomp(SECCOMP_GET_NOTIF_SIZES, 0, &sizes) == -1)
        errExit("Tracer: seccomp-SECCOMP_GET_NOTIF_SIZES");

    req = malloc(sizes.seccomp_notif);
    if (req == NULL)
        errExit("Tracer: malloc");

    resp = malloc(sizes.seccomp_notif_resp);
    if (resp == NULL)
        errExit("Tracer: malloc");

    /* Loop handling notifications */

    for (;;) {
        /* Wait for next notification, returning info in '*req' */

        bzero(req, sizes.seccomp_notif);
        bzero(resp, sizes.seccomp_notif_resp);

        if (ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_RECV, req) == -1)
            errExit("Tracer: ioctlSECCOMP_IOCTL_NOTIF_RECV");

        if(opts->debug) printf("Tracer: got notification for PID %d; ID is %llx\n",
                req->pid, req->id);

        /* Access the memory of the target process in order to discover
           the syscall arguments */

        snprintf(path, sizeof(path), "/proc/%d/mem", req->pid);

        procMem = open(path, O_RDWR);
        if (procMem == -1)
            errExit("Tracer: open");

        /* Check that the process whose info we are accessing is still alive */

        checkNotificationIdIsValid(notifyFd, req->id, "post-open", opts);

        /* Since, the SECCOMP_IOCTL_NOTIF_ID_VALID operation (performed in
           checkNotificationIdIsValid()) succeeded, we know that the
           /proc/PID/mem file descriptor that we opened corresponded to the
           process for which we received a notification. If that process
           subsequently terminates, then read() on that file descriptor will
           return 0 (EOF). This can be tested by (1) uncommenting the sleep()
           call below (and rebuilding the program); (2) running the program
           with flags to ensure that the tracer is not killed if the target
           dies; and (3) killing the target process during the sleep(). */

        // if(opts->debug) printf("About to sleep in target\n");
        // sleep(15);

        /* Seek to the location containing the pathname argument (i.e., the
           first argument) of the mkdir(2) call and read that pathname */

        int socketfd = req->data.args[0];
        intptr_t addrptr = req->data.args[1];
        size_t addrlen = req->data.args[2];
        if(opts->debug) printf("Tracer: bind(%d, 0x%llx, %lld, %lld, %lld, %llx)\n", socketfd, addrptr, addrlen, req->data.args[3], req->data.args[4], req->data.args[5]);

        if (lseek(procMem, addrptr, SEEK_SET) == -1)
            errExit("Tracer: lseek");

        addr = malloc(addrlen);
        if (resp == NULL)
            errExit("Tracer: malloc");

        ssize_t s = read(procMem, addr, addrlen);
        if (s == -1)
            errExit("read");
        else if (s == 0) {
            if(opts->debug) fprintf(stderr, "Tracer: read returned EOF\n");
            exit(EXIT_FAILURE);
        }

        char addrstring[PATH_MAX];
        if(opts->debug) {
            printf("Tracer: %p = %s\n", (void*) addrptr,
                    get_ip_str(addr, addrstring, sizeof(addrstring)));
            for(int i = 0; i < addrlen; ++i) {
                if(i == 0) printf("Tracer bind addr:");
                printf(" %02x", ((char*) addr)[i]);
                if(i == addrlen - 1) printf("\n");
            }
        }

        if(opts->debug) printf("Tracer: bind(%d, %s)\n", socketfd, get_ip_str(addr, addrstring, sizeof(addrstring)));

        /* The response to the notification includes the notification ID */

        resp->id = req->id;
        resp->flags = 0;        /* Must be zero as at Linux 5.0 */
        resp->val = 0;          /* Success return value is 0 */
        resp->error = 0;

        if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6) {

            /* Continue the syscall. This is not secure at all, but we don't
             * care for now */

            resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;

        } else {

            /* Continue the syscall. ideally we should filter the IP address and
             * make sure it is allowed, but this is not yet implemented */

            // use ptrace (most secure) https://github.com/briceburg/fdclose/blob/master/src/ptrace_do/libptrace_do.c
            // (but will that call seccomp recursively ???)
            // or modify process memory and return with SECCOMP_USER_NOTIF_FLAG_CONTINUE

            /*
            snprintf(path, sizeof(path), "/proc/%d/fd/%d", req->pid, socketfd);

            int sock = open(path, 0);
            if (sock == -1)
                errExit("Tracer: open(sock)");

            resp->error = bind(sock, addr, addrlen);

            if(opts->debug) printf("Tracer: bind() = %d", resp->error);
            */

            resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;

            struct sockaddr *replacement = malloc(addrlen);
            if (replacement == NULL)
                errExit("Tracer: malloc");
            memcpy(replacement, addr, addrlen);

            int newfd;
            int matchres = matchAllAddr(opts->map, replacement, &newfd, opts);
            if(matchres < 0) {
                resp->flags = 0;
                resp->error = -matchres;
            } else if(matchres == 2) {
                resp->flags = 0;
                resp->error = -EINVAL;
            } else if(matchres == 1) {
                char repladdrstring[PATH_MAX];
                if(!opts->quiet) printf("force-bind: replace %s with %s\n",
                        get_ip_str(addr, addrstring, sizeof(addrstring)),
                        get_ip_str(replacement, repladdrstring, sizeof(repladdrstring)));

                if (lseek(procMem, addrptr, SEEK_SET) == -1)
                    errExit("force-bind: lseek");

                if(opts->debug) {
                    for(int i = 0; i < addrlen; ++i) {
                        if(i == 0) printf("Tracer write addr:");
                        printf(" %02x", ((char*) replacement)[i]);
                        if(i == addrlen - 1) printf("\n");
                    }
                }

                ssize_t s = write(procMem, replacement, addrlen);
                if (s == -1)
                    errExit("read");
                else if (s != addrlen) {
                    fprintf(stderr, "force-bind: short write\n");
                    exit(EXIT_FAILURE);
                }

                if(opts->debug) {

                    if (lseek(procMem, addrptr, SEEK_SET) == -1)
                        errExit("Tracer: lseek");

                    free(addr);
                    addr = malloc(addrlen);
                    if (resp == NULL)
                        errExit("Tracer: malloc");

                    ssize_t s = read(procMem, addr, addrlen);
                    if (s == -1)
                        errExit("read");
                    else if (s == 0) {
                        if(opts->debug) fprintf(stderr, "Tracer: read returned EOF\n");
                        exit(EXIT_FAILURE);
                    }

                    printf("Tracer: %p = %s\n", (void*) addrptr,
                            get_ip_str(addr, addrstring, sizeof(addrstring)));

                    for(int i = 0; i < addrlen; ++i) {
                        if(i == 0) printf("Tracer bind addr:");
                        printf(" %02x", ((char*) addr)[i]);
                        if(i == addrlen - 1) printf("\n");
                    }
                }

                free(replacement);
            }

        }

        free(addr);

        if (close(procMem) == -1)
            errExit("close-/proc/PID/mem");

        /* Provide a response to the target process */

        if (ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_SEND, resp) == -1) {
            if (errno == ENOENT) {
                if(opts->debug) printf("Tracer: response failed with ENOENT; perhaps target "
                        "process's syscall was interrupted by signal?\n");
            } else {
                perror("ioctl-SECCOMP_IOCTL_NOTIF_SEND");
            }
        }
        if(opts->debug) printf("Tracer: notification sent.\n");
    }
}

/* Implementation of the tracer process; create a child process that:

   (1) obtains the seccomp notification file descriptor from 'sockPair[1]';
   (2) handles notifications that arrive on that file descriptor.

   The function return value is the PID of the child process. */

static pid_t
tracerProcess(int sockPair[2], struct cmdLineOpts *opts)
{
    pid_t tracerPid;

    tracerPid = fork();
    if (tracerPid == -1)
        errExit("fork");

    if (tracerPid > 0)          /* In parent, return PID of child */
        return tracerPid;

    /* Child falls through to here */

    if(opts->debug) printf("Tracer: PID = %ld\n", (long) getpid());

    /* Receive the notification file descriptor from the target process */

    int notifyFd = recvfd(sockPair[1]);
    if (notifyFd == -1)
        errExit("recvfd");

    closeSocketPair(sockPair);  /* We no longer need the socket pair */

    /* Handle notifications */

    watchForNotifications(notifyFd, opts);

    exit(EXIT_SUCCESS);         /* NOTREACHED */
}

static int
wait_for_ptrace(pid_t target, struct cmdLineOpts *opts){
    int status;

    while (1) {
        ptrace(PTRACE_CONT, target, 0, 0);
        waitpid(target, &status, 0);
        if(opts->debug) printf("Tracer: [waitpid status: 0x%08x]\n", status);
        /* Is it our filter for the open syscall? */
        if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8)) &&
            ptrace(PTRACE_PEEKUSER, target,
                   sizeof(long)*ORIG_RAX, 0) == __NR_bind)
            return 0;
        if (WIFEXITED(status))
            return 1;
    }
}

static void ptrace_read_bind_args(pid_t target, struct user_regs_struct *regs, int *sockfd, struct sockaddr** addr, socklen_t *addrlen, bool debug) {
    //*sockfd          = (int)       ptrace(PTRACE_PEEKUSER, target, sizeof(long)*RDI, 0);
    //intptr_t addrptr = (intptr_t)  ptrace(PTRACE_PEEKUSER, target, sizeof(long)*RSI, 0);
    //*addrlen         = (socklen_t) ptrace(PTRACE_PEEKUSER, target, sizeof(long)*RDX, 0);

    *sockfd          = (int)       regs->rdi;
    intptr_t addrptr = (intptr_t)  regs->rsi;
    *addrlen         = (socklen_t) regs->rdx;

    if (debug) {
        printf("Tracer: intercept bind(%ld, %p, %ld)\n", *sockfd, (void*) addrptr, *addrlen);
    }

    // reserve extra space in case the addrlen is not a multiple of sizeof(long)
    char buffer[*addrlen + sizeof(long)];

    // Get the address from the process memory
    for (int j = 0; j < *addrlen; j += sizeof(long)) {
        long word = ptrace(PTRACE_PEEKDATA, target, addrptr + j, NULL);
        memcpy(&buffer[j], &word, sizeof(long));
        if (debug) {
            printf("Tracer: read address 0x%p+0x%02x %08x\n", (void*) addrptr, j, word);
        }
    }

    // prepare the address buffer
    *addr = malloc(*addrlen);
    if (*addr == NULL)
        errExit("Tracer: malloc");

    // Copy the address to the buffer
    memcpy(*addr, buffer, *addrlen);
}

static bool ptrace_put_bind_args(pid_t target, struct user_regs_struct *regs, int sockfd, struct sockaddr* addr, socklen_t addrlen, bool debug) {
    int       t_sockfd  = (int)       regs->rdi;
    intptr_t  addrptr   = (intptr_t)  regs->rsi;
    socklen_t t_addrlen = (socklen_t) regs->rdx;

    if (t_addrlen < addrlen) {
        return false;
    }

    regs->rdi = sockfd;
    regs->rdx = addrlen;

    const char *buffer = (const char*) addr;

    // Get the address from the process memory
    for (int j = 0; j < addrlen; j += sizeof(long)) {
        size_t nextlen = j + sizeof(long);
        long word = 0;
        if (nextlen <= addrlen) {
            // nominal case, there is enough bytes to read buffer and to write
            // to target
            word = *((const long*) &buffer[j]);
        } else if (nextlen > t_addrlen) {
            // there is not enough room on the target to write a full word
            word = ptrace(PTRACE_PEEKDATA, target, addrptr + j, NULL);
            memcpy(&word, &buffer[j], addrlen - j);
        } else {
            // there is enough room on the target, but not enough to read
            // locally
            memcpy(&word, &buffer[j], addrlen - j);
        }
        ptrace(PTRACE_POKEDATA, target, addrptr + j, word);
    }
    return true;
}

static void
process_ptrace(pid_t target, struct cmdLineOpts *opts) {
    while(1) {
        /* Wait for open syscall start */
        if (wait_for_ptrace(target, opts) != 0) break;

        /* Find out file and re-direct if it is the target */
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, target, 0, &regs);

        int socketfd;
        socklen_t addrlen;
        struct sockaddr *addr;

        ptrace_read_bind_args(target, &regs, &socketfd, &addr, &addrlen, opts->debug);

        if(opts->debug) {
            char addrstring[PATH_MAX];
            printf("Tracer: intercept bind(%d, %s)\n", socketfd, get_ip_str(addr, addrstring, sizeof(addrstring)));
        }

        if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6) {
            continue;
        } else {
            struct sockaddr *replacement = malloc(addrlen);
            if (replacement == NULL)
                errExit("Tracer: malloc");
            memcpy(replacement, addr, addrlen);

            int sourcefd;
            int matchres = matchAllAddr(opts->map, replacement, &sourcefd, opts);
            if(matchres < 0) {
                int errnum = -matchres;
                // Return an error, first change syscall number to -1 (invalid)
                regs.orig_rax = -1;
                ptrace(PTRACE_SETREGS, target, 0, &regs);
                // Run the syscall (will do nothing)
                ptrace(PTRACE_SYSCALL, target, 0, 0);
                waitpid(target, 0, 0);
                // Return the error
                regs.rax = -errnum;
                ptrace(PTRACE_SETREGS, target, 0, &regs);
            } else if(matchres == 1) {
                if(opts->debug) printf("Tracer: replace address in memory\n");
                // Replace network address
                if(!ptrace_put_bind_args(target, &regs, socketfd, replacement, addrlen, opts->debug)) {
                    fprintf(stderr, "force-bind: short write, cannot fit %d bytes into %d\n", addrlen, (socklen_t) regs.rdx);
                    exit(EXIT_FAILURE);
                }

                ptrace(PTRACE_SETREGS, target, 0, &regs);
            } else if(matchres == 2) {
                if(opts->debug) printf("Tracer: replace system-call by dup2(%d, %d)\n", sourcefd, socketfd);
                // Replace file descriptor
                // replace orig_rax=__NR_bind rdi=socketfd rsi=addr rdx=addrlen
                // with    orig_rax=__NR_dup2 rdi=oldfd    rsi=newfd
                regs.orig_rax = __NR_dup2;
                regs.rdi      = sourcefd;
                regs.rsi      = socketfd;
                ptrace(PTRACE_SETREGS, target, 0, &regs);
                // Run the syscall (will do nothing)
                ptrace(PTRACE_SYSCALL, target, 0, 0);
                waitpid(target, 0, 0);
                // Get registers from dup2() response
                ptrace(PTRACE_GETREGS, target, 0, &regs);
                // Return 0 on success, else the error
                if(regs.rax > 0) regs.rax = 0;
                ptrace(PTRACE_SETREGS, target, 0, &regs);
            }

            free(replacement);
            free(addr);
        }
    }
}

static struct sockaddr *
copyAddr(struct addrinfo *info) {
    struct sockaddr *res = malloc(info->ai_addrlen);
    memcpy(res, info->ai_addr, info->ai_addrlen);
    return res;
}

static struct mapping*
parseMap(const char *map0, struct mapping *next, struct cmdLineOpts *opts, bool fullmatch) {
    int err;
    struct mapping *cur = malloc(sizeof(struct mapping));
    size_t maplen = map0 ? strlen(map0) : 0;
    char map[maplen+1];
    char *matchaddr = NULL;
    char *prefix = NULL;
    char *replace = NULL;

    bzero(cur, sizeof(struct mapping));
    cur->next = next;
    bzero(map, sizeof(map));
    if(map0) strncpy(map, map0, maplen);

    if (map0 && fullmatch){
        matchaddr = map;
        char *c = strchr(map, '/');
        if (c && *c) {
            prefix = c+1;
            *c = 0;
        }

        c = strchr(prefix ? prefix : map, '=');
        if (c && *c) {
            replace = c+1;
            *c = 0;
        }
    } else if(map0) {
        replace = map;
    }

    struct addrinfo hints = {
        .ai_flags = AI_PASSIVE,
        .ai_family = AF_UNSPEC
    };
    struct addrinfo *res;

    if(fullmatch && opts->debug) {
        printf("parse map %s %s %s\n", matchaddr, prefix, replace);
    }

    if(matchaddr && *matchaddr && matchaddr[0] != ':' && !prefix){
        err = getaddrinfo2(matchaddr, &hints, &res);
        if(err) {
            fprintf(stderr, "Cannot parse match %s: %s\n", matchaddr, strerror(err));
            exit(EXIT_FAILURE);
        }
        cur->addr = copyAddr(res);
        freeaddrinfo(res);
    }

    if(replace && *replace){
        size_t len = strlen(replace);
        if (len > 3 && replace[0] == 'f' && replace[1] == 'd' && (replace[2] == '=' || replace[2] == '-')) {
            int fd = atoi(&replace[3]);
            cur->replacement_fd = fd;
            cur->replacement = NULL;
            opts->require_ptrace = true;
        } else if (len > 3 && replace[0] == 's' && replace[1] == 'd' && (replace[2] == '=' || replace[2] == '-')) {
            int sd = atoi(&replace[3]);
            int fd = sd + 3;
            cur->replacement_fd = fd;
            cur->replacement = NULL;
            opts->require_ptrace = true;
        } else {
            err = getaddrinfo2(replace, &hints, &res);
            if(err) {
                fprintf(stderr, "Cannot parse replacement %s: %s\n", replace, strerror(err));
                exit(EXIT_FAILURE);
            }
            cur->replacement = copyAddr(res);
            cur->replacement_fd = 0;
            freeaddrinfo(res);
        }
    }


    if(matchaddr && *matchaddr && matchaddr[0] == ':'){

        bool num = 0;

        if(!cur->replacement || cur->replacement->sa_family == AF_INET) {
            char matchaddr4[PATH_MAX];
            snprintf(matchaddr4, PATH_MAX, "0.0.0.0%s", matchaddr);
            err = getaddrinfo2(matchaddr4, &hints, &res);
            if(err) {
                fprintf(stderr, "Cannot parse IPv4 match %s: %s\n", matchaddr, strerror(err));
                exit(EXIT_FAILURE);
            }
            cur->addr = copyAddr(res);
            cur->prefix = 32;
            freeaddrinfo(res);
            num++;
        }

        if(!cur->replacement || cur->replacement->sa_family == AF_INET6) {
            if(num) {
                next = cur;
                cur = malloc(sizeof(struct mapping));
                memcpy(cur, next, sizeof(struct mapping));
                cur->next = next;
                num--;
            }

            char matchaddr6[PATH_MAX];
            snprintf(matchaddr6, PATH_MAX, "[::]%s", matchaddr);
            err = getaddrinfo2(matchaddr6, &hints, &res);
            if(err) {
                fprintf(stderr, "Cannot parse IPv6 match %s: %s\n", matchaddr, strerror(err));
                exit(EXIT_FAILURE);
            }
            cur->addr = copyAddr(res);
            cur->prefix = 128;
            freeaddrinfo(res);
            num++;
        }

    } else {

        if(prefix) {
            cur->prefix = atoi(prefix);
        } else if (cur->addr && cur->addr->sa_family == AF_INET) {
            cur->prefix = 32;
        } else if (cur->addr && cur->addr->sa_family == AF_INET6) {
            cur->prefix = 128;
        }


        if(cur->addr && cur->replacement && cur->addr->sa_family != cur->replacement->sa_family) {
            fprintf(stderr, "Not the same address family on both sides: %s", map0);
            exit(EXIT_FAILURE);
        }

    }

    return cur;
}

static struct in_addr
netAddrIpv4(int prefix, struct in_addr *addr) {
    in_addr_t netmask = 0;
    while(prefix--){
        netmask = (netmask << 1) | 1;
    }
    struct in_addr res = { .s_addr = netmask & addr->s_addr };
    return res;
}

static struct in6_addr
netAddrIpv6(int prefix, struct in6_addr *addr) {
    struct in6_addr netmask;
    for (long i = prefix, j = 0; i > 0; i -= 8, ++j) {
        netmask.s6_addr[j] = (i >= 8) ?
            0xff :
            ( 0xffU << ( 8 - i ) ) & 0xffU;
    }
    struct in6_addr res = {};
    for(int i = 0; i < 16; i++) {
        res.s6_addr[i] = res.s6_addr[i] & netmask.s6_addr[i];
    }
    return netmask;
}

static bool
matchAddr(const struct mapping *map, const struct sockaddr *sa, const struct cmdLineOpts *opts) {
    if (map->replacement && sa->sa_family != map->replacement->sa_family) return false;
    if (!map->addr) return true;
    if (sa->sa_family != map->addr->sa_family) return false;

    switch(sa->sa_family) {
        case AF_INET: {
            struct sockaddr_in *addr = (struct sockaddr_in *) sa;
            struct sockaddr_in *map_addr = (struct sockaddr_in *) map->addr;

            /* check port number */
            if (addr->sin_port == 0) return false; // Never match outgoing connections
            if (map_addr->sin_port != 0 && map_addr->sin_port != addr->sin_port) return false;

            /* check network IP */
            struct in_addr net_addr = netAddrIpv4(map->prefix, &addr->sin_addr);
            struct in_addr map_net_addr = netAddrIpv4(map->prefix, &map_addr->sin_addr);
            if (net_addr.s_addr != map_net_addr.s_addr) return false;

            break;
        }

        case AF_INET6: {
            struct sockaddr_in6 *addr = (struct sockaddr_in6 *) sa;
            struct sockaddr_in6 *map_addr = (struct sockaddr_in6 *) map->addr;

            /* check port number */
            if (addr->sin6_port == 0) return false; // Never match outgoing connections
            if (map_addr->sin6_port != 0 && map_addr->sin6_port != addr->sin6_port) return false;

            /* check network IP */
            struct in6_addr net_addr = netAddrIpv6(map->prefix, &addr->sin6_addr);
            struct in6_addr map_net_addr = netAddrIpv6(map->prefix, &map_addr->sin6_addr);
            for(int i = 0; i < 16; ++i)
                if (net_addr.s6_addr[i] != map_net_addr.s6_addr[i]) return false;

            break;
        }

        default:
            return false;
    }

    return true;
}

static void
setReplacement(struct sockaddr *addr0, const struct sockaddr *repl0) {
    switch(addr0->sa_family) {
        case AF_INET: {
            struct sockaddr_in sa = *((struct sockaddr_in *) addr0);
            struct sockaddr_in *addr = (struct sockaddr_in *) addr0;
            struct sockaddr_in *repl = (struct sockaddr_in *) repl0;

            memcpy(addr, repl, sizeof(struct sockaddr_in));

            if(addr->sin_port == 0) {
                addr->sin_port = sa.sin_port;
            }
            break;
        }

        case AF_INET6: {
            struct sockaddr_in6 sa = *((struct sockaddr_in6 *) addr0);
            struct sockaddr_in6 *addr = (struct sockaddr_in6 *) addr0;
            struct sockaddr_in6 *repl = (struct sockaddr_in6 *) repl0;

            memcpy(addr, repl, sizeof(struct sockaddr_in6));

            if(addr->sin6_port == 0) {
                addr->sin6_port = sa.sin6_port;
            }
            break;
        }
    }
}

/* Return:
 *      0       -   does not match, continue syscall
 *      -errno  -   return -errno error
 *      1       -   match new address
 *      2       -   match file descriptor
 */
static int
matchAllAddr(const struct mapping *map, struct sockaddr *sa, int *newfd, const struct cmdLineOpts *opts) {
    switch(sa->sa_family) {
        case AF_INET: {
            struct sockaddr_in *addr = (struct sockaddr_in *) sa;
            if (addr->sin_port == 0) return 0; // Never match outgoing connections
        }
        case AF_INET6: {
            struct sockaddr_in6 *addr = (struct sockaddr_in6 *) sa;
            if (addr->sin6_port == 0) return 0; // Never match outgoing connections
        }
    }

    char addr1[PATH_MAX], addr2[PATH_MAX], addr3[PATH_MAX];
    while(map) {
        if(opts->verbose) printf("force-bind: try match %s with %s/%d (replace with %s or fd=%d)\n",
                get_ip_str(sa, addr1, sizeof(addr1)),
                get_ip_str(map->addr, addr2, sizeof(addr2)), map->prefix,
                get_ip_str(map->replacement, addr3, sizeof(addr3)),
                map->replacement_fd);
        if(matchAddr(map, sa, opts)) {
            if(map->replacement) {
                setReplacement(sa, map->replacement);
                return 1;
            } else if (map->replacement_fd) {
                *newfd = map->replacement_fd;
                return 2;
            } else {
                return -EACCES;
            }
        }
        map = map->next;
    }
    if(opts->verbose) printf("force-bind: did not match %s\n",
            get_ip_str(sa, addr1, sizeof(addr1)));
    return 0;
}

/* Diagnose an error in command-line option or argument usage */

static void
usageError(char *msg, char *pname)
{
    if (msg != NULL)
        fprintf(stderr, "%s\n", msg);

    fprintf(stderr,
        "Usage: %s [options] TARGET_PROGRAM [ARGS ...]\n", pname);
    fprintf(stderr,
        "Options\n"
        "    -h                    Help\n"
        "    -V                    Version information\n"
        "    -m MATCH=ADDR         Replace bind() matching first MATCH with ADDR\n"
        "    -b ADDR               Replace all bind() with ADDR (if same family)\n"
        "    -d                    Deny all bind()\n"
        "    -p                    Force seccomp-ptrace instead of only seccomp\n"
        "    -D                    Debug messages\n"
        "    -v                    Verbose\n"
        "    -q                    Quiet\n"
        "\n"
        "Last rules (-m, -b, -d) are applied first so you can put your general policy\n"
        "first on your command-line and any following argument can override it.\n"
        "\n"
        "With the -m rule, MATCH pattern can be:\n"
        "\n"
        "    :PORT                 Matches both IPv4 and IPv6 listening on PORT\n"
        "    ADDR:PORT/PREFIX      Matches address with given port with the netmark\n"
        "                          corresponding to PREFIX applied first on both IPs\n"
        "                          IPv6 address must be enclosed in squared brackets.\n"
        "\n"
        "In the rules, ADDR can be:\n"
        "\n"
        "    IP:PORT               Changes the bind target to specified address\n"
        "    fd=N or fd-N          dup2() the specified inherited file descriptor\n"
        "                          in place\n"
        "    sd=N or sd-N          same as fd=N but for systemd file descriptor. sd=0\n"
        "                          is thus equivalent to fd=3\n"
        "\n"
        "Examples:\n"
        "\n"
        "  * force-bind -m 0.0.0.0:80/0=127.0.0.1:8080 progname args...\n"
        "\n"
        "    Replace binds from any IPv4 address port 80 to localhost-only port\n"
        "    8080. IPv6 binds are allowed.\n"
        "\n"
        "  * force-bind -d -m '[::]:80/0=[::1]:8080' progname args...\n"
        "\n"
        "    Replace binds from any IPv6 address port 80 to localhost-only port\n"
        "    8080. IPv4 binds are denied.\n"
        "\n"
        "  * force-bind -d -b '[::1]:8081' -b '127.0.0.1:8080' progname args...\n"
        "\n"
        "    Replace binds from any IPv6 address to localhost port 8081 and from\n"
        "    any IPv4 address to localhost port 8080.\n"
        "\n"
        "  * force-bind -m ':80=sd=0' -m ':80=fd=4' progname args...\n"
        "\n"
        "    Replace any bind to port 80 using first socket from systemd socket\n"
        "    activation. Any port 81 is replaced by passed file descriptor 4.\n"
        "\n");
#ifdef VERSION
    fprintf(stderr, "\nVersion: %s\n", VERSION);
#endif
}

/* Parse command-line options, returning option info in 'opts' */

static int
parseCommandLineOptions(int argc, char *argv[], struct cmdLineOpts *opts)
{
    int opt;

    bzero(opts, sizeof(struct cmdLineOpts));
    opts->debug = false;
    opts->map = NULL;
    opts->require_ptrace = false;

    int i;
    for(i = 1; argv[i]; i++){
        const char *arg = argv[i];
        if       (!strcmp("-m", arg) && argv[i+1]) { /* Mapping */
            opts->map = parseMap(argv[++i], opts->map, opts, true);

        } else if(!strcmp("-b", arg) && argv[i+1]) { /* Bind */
            opts->map = parseMap(argv[++i], opts->map, opts, false);

        } else if(!strcmp("-d", arg)) {              /* Deny */
            opts->map = parseMap(NULL, opts->map, opts, false);

        } else if(!strcmp("-p", arg)) {              /* Ptrace */
            opts->require_ptrace = true;

        } else if(!strcmp("-D", arg)) {              /* Debug */
            opts->debug = true;

        } else if(!strcmp("-q", arg)) {              /* Quiet */
            opts->quiet = true;

        } else if(!strcmp("-v", arg)) {              /* Verbose */
            opts->verbose = true;

        } else if(!strcmp("-V", arg)) {              /* Version */
#ifdef VERSION
            printf("Version: %s\n", VERSION);
            exit(EXIT_SUCCESS);
#else
            fprintf(stderr, "No version string available\n");
            exit(EXIT_FAILURE);
#endif

        } else if(!strcmp("-h", arg)) {              /* Help */
            usageError(NULL, argv[0]);
            exit(EXIT_SUCCESS);

        } else if(*arg == '-') {
            usageError("Bad option", argv[0]);
            exit(EXIT_FAILURE);

        } else {
            break;
        }
    }

    /* There should be at least one command-line argument after the options */

    if (!argv[i]) {
        usageError("At least one pathname argument should be supplied",
                argv[0]);
        exit(EXIT_FAILURE);
    }

    return i;
}

int
main(int argc, char *argv[])
{
    pid_t targetPid, tracerPid;
    int sockPair[2];
    struct cmdLineOpts opts;

    setbuf(stdout, NULL);

    int optind = parseCommandLineOptions(argc, argv, &opts);

    /* Create a UNIX domain socket that is used to pass the seccomp
       notification file descriptor from the target process to the tracer
       process. */

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockPair) == -1)
        errExit("socketpair");

    /* Create a child process--the "target"--that installs seccomp filtering.
       The target process writes the seccomp notification file descriptor
       onto 'sockPair[0]' and then calls mkdir(2) for each directory in the
       command-line arguments. */

    targetPid = targetProcess(sockPair, &argv[optind], &opts);

    /* Create the "tracer" as another child process. This allows the parent to
       wait on the target process and then either kill or wait on the tracer
       when the target terminates. The tracer reads the seccomp notification
       file descriptor from 'sockPair[1]' and then handles the notifications
       that arrive on that file descriptor. */

    if (opts.require_ptrace) {
        if(opts.debug) printf("Tracer: use seccomp-ptrace method\n");

        /* Wait for the target process to signal STOP
         */
        int status;
        waitpid(targetPid, &status, 0);

        ptrace(PTRACE_SETOPTIONS, targetPid, 0, PTRACE_O_TRACESECCOMP);
        process_ptrace(targetPid, &opts);

    } else {

        if(opts.debug) printf("Tracer: use seccomp-only method\n");
        tracerPid = tracerProcess(sockPair, &opts);

        /* The parent process does not need the socket pair */

        closeSocketPair(sockPair);

        /* Wait for the target process to terminate */

        waitpid(targetPid, NULL, 0);
        if(opts.debug) printf("Parent: target process has terminated\n");

        /* After the target process has terminated, kill the tracer process */

        if(opts.debug) printf("Parent: killing tracer\n");
        kill(tracerPid, SIGTERM);
    }

    exit(EXIT_SUCCESS);
}
