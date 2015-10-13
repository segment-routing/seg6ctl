#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include "nlmem.h"
#include "seg6.h"

void usage(char *) __attribute__((noreturn));

void usage(char *av0)
{
    fprintf(stderr, "Usage: %s binding-sid addr\n", av0);
    exit(-1);
}

int main(int ac, char **av)
{
    struct seg6_sock *sk;
    struct in6_addr bsid, addr;
    struct nlmsghdr *msg;
    struct nlmem_cb cb;
    int ret;

    if (ac != 3)
        usage(av[0]);

    inet_pton(AF_INET6, av[1], &bsid);
    inet_pton(AF_INET6, av[2], &addr);

    sk = seg6_socket_create(16*getpagesize(), 64);

    msg = nlmem_msg_create(sk->nlm_sk, SEG6_CMD_ADDBIND, NLM_F_REQUEST);

    nlmem_nla_put(sk->nlm_sk, msg, SEG6_ATTR_DST, sizeof(struct in6_addr), &bsid);
    nlmem_nla_put_u8(sk->nlm_sk, msg, SEG6_ATTR_BIND_OP, SEG6_BIND_OVERRIDE_NEXT);
    nlmem_nla_put(sk->nlm_sk, msg, SEG6_ATTR_BIND_DATA, sizeof(struct in6_addr), &addr);
    nlmem_nla_put_u32(sk->nlm_sk, msg, SEG6_ATTR_BIND_DATALEN, sizeof(struct in6_addr));

    ret = seg6_send_and_recv(sk, msg, &cb);
    if (ret)
        fprintf(stderr, "seg6_send_and_recv(): %s\n", strerror(ret));

    seg6_socket_destroy(sk);

    return 0;
}
