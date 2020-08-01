#ifndef _FORCE_BIND_SECCOMP_IP_FUNCS_H_
#define _FORCE_BIND_SECCOMP_IP_FUNCS_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>


static int getaddrinfo2(const char *nodeport0,
                       const struct addrinfo *hints,
                       struct addrinfo **res) {
    size_t len = strlen(nodeport0);
    char nodeport[len+1];
    strncpy(nodeport, nodeport0, len+1);

    char *node = nodeport, *service = nodeport;

    if(*nodeport == '['){
        char *c = strchr(nodeport, ']');
        if(c && *c) {
            *c = 0;
            node = nodeport + 1;
            service = c + 1;
        }
    }

    char *c = strchr(service, ':');
    if(c && *c) {
        *c = 0;
        service = c+1;
    } else {
        service = NULL;
    }

    return getaddrinfo(node, service, hints, res);
}

static char *
get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen)
{
#define sa4 ((struct sockaddr_in *)sa)
#define sa6 ((struct sockaddr_in6 *)sa)
    char addr[1024];

    if(!sa) {
        strncpy(s, "(null)", maxlen);
        return s;
    }

    switch(sa->sa_family) {
        case AF_INET: {
            inet_ntop(AF_INET, &(sa4->sin_addr), addr, sizeof(addr));
            snprintf(s, maxlen, "%s:%d", addr, ntohs(sa4->sin_port));
            break;
        }

        case AF_INET6:
            inet_ntop(AF_INET6, &(sa6->sin6_addr), addr, sizeof(addr));
            snprintf(s, maxlen, "[%s]:%d", addr, ntohs(sa6->sin6_port));
            break;

        default:
            return NULL;
    }

    return s;
#undef sa4
#undef sa6
}

#endif
