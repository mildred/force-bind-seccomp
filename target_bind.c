#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "ip_funcs.h"

#define BUF_SIZE 500

int main(int argc, char *argv[]) {
   char addrstr[1024];
   struct addrinfo hints;
   struct addrinfo *result, *rp;
   int sfd, s;
   struct sockaddr_storage peer_addr;
   socklen_t peer_addr_len;
   ssize_t nread;
   char buf[BUF_SIZE];

   if (argc != 2) {
       fprintf(stderr, "Usage: %s port\n", argv[0]);
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

   s = getaddrinfo(NULL, argv[1], &hints, &result);
   if (s != 0) {
       fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
       exit(EXIT_FAILURE);
   }

   /* getaddrinfo() returns a list of address structures.
      Try each address until we successfully bind(2).
      If socket(2) (or bind(2)) fails, we (close the socket
      and) try the next address. */

   for (rp = result; rp != NULL; rp = rp->ai_next) {
       printf("socket(%d, %d, %d)\n", rp->ai_family, rp->ai_socktype, rp->ai_protocol);
       sfd = socket(rp->ai_family, rp->ai_socktype,
               rp->ai_protocol);
       if (sfd == -1)
           continue;

       printf("bind(%d, %p, %d)\n", sfd, (void*) rp->ai_addr, rp->ai_addrlen);
       printf("(before) %p = %s\n", rp->ai_addr, get_ip_str(rp->ai_addr, addrstr, sizeof(addrstr)));
       if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0) {
           printf("(after)  %p = %s\n", rp->ai_addr, get_ip_str(rp->ai_addr, addrstr, sizeof(addrstr)));
           break;                  /* Success */
       }
       printf("(after)  %p = %s\n", rp->ai_addr, get_ip_str(rp->ai_addr, addrstr, sizeof(addrstr)));

       close(sfd);
   }

   if (rp == NULL) {               /* No address succeeded */
       perror("Could not bind");
       exit(EXIT_FAILURE);
   }

   freeaddrinfo(result);           /* No longer needed */

   /* Read datagrams and echo them back to sender */

   for (;;) {
       printf("recvfrom(%d, %p, %d, ...)\n", sfd, buf, BUF_SIZE);
       peer_addr_len = sizeof(struct sockaddr_storage);
       nread = recvfrom(sfd, buf, BUF_SIZE, 0,
               (struct sockaddr *) &peer_addr, &peer_addr_len);
       if (nread == -1)
           continue;               /* Ignore failed request */

       char host[NI_MAXHOST], service[NI_MAXSERV];

       s = getnameinfo((struct sockaddr *) &peer_addr,
                       peer_addr_len, host, NI_MAXHOST,
                       service, NI_MAXSERV, NI_NUMERICSERV);
       if (s == 0)
           printf("Received %zd bytes from %s:%s\n",
                   nread, host, service);
       else
           fprintf(stderr, "getnameinfo: %s\n", gai_strerror(s));

       if (sendto(sfd, buf, nread, 0,
                   (struct sockaddr *) &peer_addr,
                   peer_addr_len) != nread)
           fprintf(stderr, "Error sending response\n");
   }
}
