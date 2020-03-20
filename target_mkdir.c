#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/prctl.h>
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

int main(int argc, char **argv) {
    int s;

    for (char **ap = argv+1; *ap != NULL; ap++) {
        printf("\nTarget process: about to make directory \"%s\"\n", *ap);
        s = mkdir(*ap, 0600);
        if (s == -1)
            perror("Target process: mkdir");
        else
            printf("Target process: SUCCESS: mkdir(2) returned = %d\n", s);
    }

    printf("Target process: terminating\n");
    exit(EXIT_SUCCESS);
}
