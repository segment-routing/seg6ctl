#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "seg6.h"

void usage(char *) __attribute__((noreturn));

/* just count packets */
void parse_packet_in(struct seg6_sock *sk, struct nlattr **attrs)
{
    static int cnt;

    printf("%d\n", ++cnt);
}

void usage(char *av0)
{
    fprintf(stderr, "Usage: %s segment\n", av0);
    exit(-1);
}

int main(int ac, char **av)
{
    struct seg6_sock *sk;
    struct in6_addr in6;
    struct nl_msg *msg;

    if (ac != 2)
        usage(av[0]);

    inet_pton(AF_INET6, av[1], &in6);

    sk = seg6_socket_create();
    seg6_set_callback(sk, SEG6_CMD_PACKET_IN, parse_packet_in);

    msg = seg6_new_msg(sk, SEG6_CMD_ADDBIND);

    nla_put(msg, SEG6_ATTR_DST, sizeof(struct in6_addr), &in6);
    nla_put_u8(msg, SEG6_ATTR_BIND_OP, SEG6_BIND_SERVICE);
    nla_put_u32(msg, SEG6_ATTR_FLAGS, 0x1); /* non-blocking */
    nla_put(msg, SEG6_ATTR_BIND_DATA, 0, NULL);
    nla_put_u32(msg, SEG6_ATTR_BIND_DATALEN, 0);

    seg6_send_msg(sk, msg, 1); /* keepalive */

    seg6_socket_destroy(sk);

    return 0;
}
