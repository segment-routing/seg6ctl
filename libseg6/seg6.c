#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <errno.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include "seg6.h"
#include "nlmem.h"

#define MIN(a,b) ((a) < (b) ? (a) : (b))

static struct nla_policy seg6_genl_policy[SEG6_ATTR_MAX + 1] = {
    [SEG6_ATTR_DST]         = { .type = NLA_UNSPEC, .maxlen = sizeof(struct in6_addr) },
    [SEG6_ATTR_DSTLEN]      = { .type = NLA_U32, },
    [SEG6_ATTR_SEGLISTID]   = { .type = NLA_U16, },
    [SEG6_ATTR_FLAGS]       = { .type = NLA_U32, },
    [SEG6_ATTR_HMACKEYID]   = { .type = NLA_U8, },
    [SEG6_ATTR_SEGMENTS]    = { .type = NLA_UNSPEC, },
    [SEG6_ATTR_SEGLEN]      = { .type = NLA_U32, },
    [SEG6_ATTR_SEGINFO]     = { .type = NLA_NESTED, },
    [SEG6_ATTR_SECRET]      = { .type = NLA_UNSPEC, .maxlen = 64 },
    [SEG6_ATTR_SECRETLEN]   = { .type = NLA_U8, },
    [SEG6_ATTR_ALGID]       = { .type = NLA_U8, },
    [SEG6_ATTR_HMACINFO]    = { .type = NLA_NESTED, },
    [SEG6_ATTR_BIND_OP]         = { .type = NLA_U8, },
    [SEG6_ATTR_BIND_DATA]       = { .type = NLA_UNSPEC, },
    [SEG6_ATTR_BIND_DATALEN]    = { .type = NLA_U32, },
    [SEG6_ATTR_BINDINFO]        = { .type = NLA_NESTED, },
    [SEG6_ATTR_PACKET_DATA]     = { .type = NLA_UNSPEC, },
    [SEG6_ATTR_PACKET_LEN]      = { .type = NLA_U32, },
    [SEG6_ATTR_POLICY_DATA]     = { .type = NLA_UNSPEC, },
    [SEG6_ATTR_POLICY_LEN]      = { .type = NLA_U32, },
};

struct seg6_sock *seg6_socket_create(int block_size, int block_nr)
{
    struct nlmem_sock *nlm_sk;
    struct seg6_sock *sk;
    long i;
    int frame_size = MIN(16384, block_size);

    struct nl_mmap_req req = {
        .nm_block_size  = block_size,
        .nm_block_nr    = block_nr,
        .nm_frame_size  = frame_size,
        .nm_frame_nr    = block_nr * block_size / frame_size,
    };

    nlm_sk = nlmem_sock_create(&req, "SEG6");
    if (!nlm_sk)
        return NULL;

    sk = malloc(sizeof(*sk));
    sk->nlm_sk = nlm_sk;

    sk->callbacks = malloc(__SEG6_CMD_MAX*2*sizeof(void *));
    for (i = 0; i < __SEG6_CMD_MAX; i++) {
        sk->callbacks[i*2] = (void *)i;
        sk->callbacks[i*2+1] = NULL;
    }

    return sk;
}

void seg6_socket_destroy(struct seg6_sock *sk)
{
    nlmem_sock_destroy(sk->nlm_sk);
    free(sk);
}

struct nlmsghdr *seg6_new_msg(struct seg6_sock *sk, int cmd)
{
    struct nlmsghdr *msg;

    msg = nlmem_msg_create(sk->nlm_sk, cmd, NLM_F_REQUEST | NLM_F_ACK);

    return msg;
}

void seg6_set_callback(struct seg6_sock *sk, int cmd, void (*callback)(struct seg6_sock *, struct nlattr **, struct nlmsghdr *))
{
    sk->callbacks[cmd*2+1] = callback;
}

static int nl_recv_cb(struct nlmem_sock *nlm_sk __unused, struct nlmsghdr *msg, void *arg)
{
    struct genlmsghdr *gnlh = nlmsg_data(msg);
    struct nlattr *attrs[SEG6_ATTR_MAX + 1];
    struct seg6_sock *sk;
    void (*callback)(struct seg6_sock *, struct nlattr **, struct nlmsghdr *);

    sk = (struct seg6_sock *)arg;

    if (genlmsg_parse(msg, 0, attrs, SEG6_ATTR_MAX, seg6_genl_policy)) {
        perror("genlmsg_parse");
        return NL_SKIP;
    }

    callback = sk->callbacks[gnlh->cmd*2+1];
    if (callback)
        callback(sk, attrs, msg);

    return NL_SKIP;
}

static int nl_recv_cb_delayed(struct nlmem_sock *nlm_sk __unused, struct nlmsghdr *msg, void *arg)
{
    struct genlmsghdr *gnlh = nlmsg_data(msg);
    struct nlattr **attrs;
    struct seg6_sock *sk;
    void (*callback)(struct seg6_sock *, struct nlattr **, struct nlmsghdr *);

    sk = (struct seg6_sock *)arg;

    if((attrs = (struct nlattr **) malloc(sizeof(struct nlattr *) * SEG6_ATTR_MAX)) == NULL){
        perror("attrs malloc");
        return NL_SKIP;
    }

    if (genlmsg_parse(msg, 0, attrs, SEG6_ATTR_MAX, seg6_genl_policy)) {
        perror("genlmsg_parse");
        return NL_SKIP;
    }

    callback = sk->callbacks[gnlh->cmd*2+1];
    if (callback)
        callback(sk, attrs, msg);

    return NL_SKIP;
}

static int nl_recv_err(struct nlmem_sock *nlm_sk __unused, struct nlmsghdr *hdr, void *arg)
{
    int *error = arg;
    struct nlmsgerr *err = nlmsg_data(hdr);

    *error = err->error;

    return NL_STOP;
}

static int nl_recv_ack(struct nlmem_sock *nlm_sk __unused, struct nlmsghdr *hdr __unused, void *arg)
{
    int *error = arg;

    *error = 0;

    return NL_STOP;
}

static int nl_recv_invalid(struct nlmem_sock *nlm_sk __unused, struct nlmsghdr *hdr __unused, void *arg __unused)
{
    return NL_STOP;
}

int seg6_send_and_recv(struct seg6_sock *sk, struct nlmsghdr *msg, struct nlmem_cb *ucb)
{
    struct nlmem_cb *cb;
    int err = 0;

    nlmem_send_msg(sk->nlm_sk, msg);

    cb = &sk->nlm_sk->cb;

    if(sk->nlm_sk->delayed_release)
        nlmem_set_cb(cb, NLMEM_CB_VALID, nl_recv_cb_delayed, sk);
    else
        nlmem_set_cb(cb, NLMEM_CB_VALID, nl_recv_cb, sk);

    nlmem_set_cb(cb, NLMEM_CB_ACK, nl_recv_ack, &err);
    nlmem_set_cb(cb, NLMEM_CB_ERR, nl_recv_err, &err);
    nlmem_set_cb(cb, NLMEM_CB_INVALID, nl_recv_invalid, sk);

    if (ucb) {
        if (ucb->cb_set[NLMEM_CB_VALID])
            nlmem_set_cb(cb, NLMEM_CB_VALID, ucb->cb_set[NLMEM_CB_VALID], ucb->cb_args[NLMEM_CB_VALID]);
        if (ucb->cb_set[NLMEM_CB_ACK])
            nlmem_set_cb(cb, NLMEM_CB_ACK, ucb->cb_set[NLMEM_CB_ACK], ucb->cb_args[NLMEM_CB_ACK]);
        if (ucb->cb_set[NLMEM_CB_ERR])
            nlmem_set_cb(cb, NLMEM_CB_ERR, ucb->cb_set[NLMEM_CB_ERR], ucb->cb_args[NLMEM_CB_ERR]);
        if (ucb->cb_set[NLMEM_CB_INVALID])
            nlmem_set_cb(cb, NLMEM_CB_INVALID, ucb->cb_set[NLMEM_CB_INVALID], ucb->cb_args[NLMEM_CB_INVALID]);
    }

    nlmem_recv_loop(sk->nlm_sk, cb);

    return err;
}
