#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "ip_funcs.h"

#define BUF_SIZE 500

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)

int main(int argc, char *argv[]) {
   char addrstr[1024];
   struct addrinfo hints;
   struct addrinfo *result, *rp;
   int sfd, s;
   struct sockaddr_storage peer_addr;
   socklen_t peer_addr_len;
   ssize_t nread;
   char buf[BUF_SIZE];

   if (argc < 4) {
       fprintf(stderr, "Usage: %s addr port\n", argv[0]);
       exit(EXIT_FAILURE);
   }

   memset(&hints, 0, sizeof(struct addrinfo));
   hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
   hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
   hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
   hints.ai_protocol = 0;          /* Any protocol */
   hints.ai_canonname = NULL;
   hints.ai_addr = NULL;
   hints.ai_next = NULL;

   s = getaddrinfo(argv[1], argv[2], &hints, &result);
   if (s != 0) {
       fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
       exit(EXIT_FAILURE);
   }

   /* getaddrinfo() returns a list of address structures.
      Try each address until we successfully bind(2).
      If socket(2) (or bind(2)) fails, we (close the socket
      and) try the next address. */

   for (rp = result; rp != NULL; rp = rp->ai_next) {
       printf("parent: socket(%d, %d, %d)\n", rp->ai_family, rp->ai_socktype, rp->ai_protocol);
       sfd = socket(rp->ai_family, rp->ai_socktype,
               rp->ai_protocol);
       if (sfd == -1)
           continue;

       printf("parent: bind(%d, %p, %d)\n", sfd, (void*) rp->ai_addr, rp->ai_addrlen);
       printf("parent (before): %p = %s\n", rp->ai_addr, get_ip_str(rp->ai_addr, addrstr, sizeof(addrstr)));
       if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0) {
           printf("parent (after):  %p = %s\n", rp->ai_addr, get_ip_str(rp->ai_addr, addrstr, sizeof(addrstr)));
           break;                  /* Success */
       }
       printf("parent (after):  %p = %s\n", rp->ai_addr, get_ip_str(rp->ai_addr, addrstr, sizeof(addrstr)));

       close(sfd);
   }

   if (rp == NULL) {               /* No address succeeded */
       perror("Could not bind");
       exit(EXIT_FAILURE);
   }

   if(sfd != 3) {
      dup2(3, sfd);
   }

   pid_t child = fork();
   if (child == 0) {
      char pid_str[64];
      snprintf(pid_str, 64, "%d", getpid());

      setenv("LISTEN_FDS", "1", 1);
      setenv("LISTEN_PID", pid_str, 1);

      char **args = &argv[3];
      if(execvp(args[0], args) == -1)
         errExit("execvp");
      exit(EXIT_FAILURE);
   }

   waitpid(child, 0, 0);
   exit(EXIT_SUCCESS);
}
