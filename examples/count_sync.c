#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include "nlmem.h"
#include "seg6.h"

int counter;

void usage(char *) __attribute__((noreturn));

/* just count packets */
void parse_packet_in(struct seg6_sock *sk, struct nlattr **attrs)
{
    int pkt_len;
    char *pkt_data;
    struct nlmsghdr *msg;

    ++counter;

    pkt_len = nla_get_u32(attrs[SEG6_ATTR_PACKET_LEN]);
    pkt_data = nla_data(attrs[SEG6_ATTR_PACKET_DATA]);

    msg = nlmem_msg_create(sk->nlm_sk, SEG6_CMD_PACKET_OUT, NLM_F_REQUEST);

    nlmem_nla_put_u32(sk->nlm_sk, msg, SEG6_ATTR_PACKET_LEN, pkt_len);
    nlmem_nla_put(sk->nlm_sk, msg, SEG6_ATTR_PACKET_DATA, pkt_len, pkt_data);

    nlmem_send_msg(sk->nlm_sk, msg);
}

void usage(char *av0)
{
    fprintf(stderr, "Usage: %s segment\n", av0);
    exit(-1);
}

void sigint(int sig __unused)
{
    printf("%d\n", counter);
}

int nl_recv_ack(struct nlmem_sock *nlm_sk __unused, struct nlmsghdr *hdr __unused, void *arg __unused)
{
    return NL_SKIP;
}

int main(int ac, char **av)
{
    struct seg6_sock *sk;
    struct in6_addr in6;
    struct nlmsghdr *msg;
    struct nlmem_cb cb;
    int ret;

    counter = 0;
    signal(SIGINT, sigint);

    if (ac != 2)
        usage(av[0]);

    inet_pton(AF_INET6, av[1], &in6);

    /* 
     * seg6_socket_create(block_size, block_nr)
     * mem usage = block_size * block_nr * 2
     * default settings = 8MB usage for 4K pages
     * increase block_size and not block_nr if needed
     */
    sk = seg6_socket_create(16*getpagesize(), 64);

    seg6_set_callback(sk, SEG6_CMD_PACKET_IN, parse_packet_in);

    msg = nlmem_msg_create(sk->nlm_sk, SEG6_CMD_ADDBIND, NLM_F_REQUEST);

    nlmem_nla_put(sk->nlm_sk, msg, SEG6_ATTR_DST, sizeof(struct in6_addr), &in6);
    nlmem_nla_put_u8(sk->nlm_sk, msg, SEG6_ATTR_BIND_OP, SEG6_BIND_SERVICE);
    nlmem_nla_put_u32(sk->nlm_sk, msg, SEG6_ATTR_FLAGS, 0); /* blocking */
    nlmem_nla_put(sk->nlm_sk, msg, SEG6_ATTR_BIND_DATA, 0, NULL);
    nlmem_nla_put_u32(sk->nlm_sk, msg, SEG6_ATTR_BIND_DATALEN, 0);

    memset(&cb, 0, sizeof(cb));

    /*
     * user-defined callback for ack: just skip to next packet.
     * default action is to stop processing upon ack reception but
     * we do not want that with binding segment processing
     */
    nlmem_set_cb(&cb, NLMEM_CB_ACK, nl_recv_ack, NULL);

    ret = seg6_send_and_recv(sk, msg, &cb);
    if (ret)
        fprintf(stderr, "seg6_send_and_recv(): %s\n", strerror(ret));

    seg6_socket_destroy(sk);

    return 0;
}
