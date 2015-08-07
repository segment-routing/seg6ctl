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
};

struct seg6_sock *seg6_socket_create(void)
{
    struct nl_sock *nl_sk;
    int family_req;
    struct seg6_sock *sk;
    long i;

    sk = malloc(sizeof(*sk));

    nl_sk = nl_socket_alloc();
    if (genl_connect(nl_sk)) {
        perror("genl_connect");
        return NULL;
    }

    family_req = genl_ctrl_resolve(nl_sk, "SEG6");
    nl_socket_disable_seq_check(nl_sk);

    sk->nl_sk = nl_sk;
    sk->family_req = family_req;

    sk->callbacks = malloc(__SEG6_CMD_MAX*2*sizeof(void *));
    for (i = 0; i < __SEG6_CMD_MAX; i++) {
        sk->callbacks[i*2] = (void *)i;
        sk->callbacks[i*2+1] = NULL;
    }

    return sk;
}

void seg6_socket_destroy(struct seg6_sock *sk)
{
    nl_socket_free(sk->nl_sk);
    free(sk);
}

struct nl_msg *seg6_new_msg(struct seg6_sock *sk, int cmd)
{
    struct nl_msg *msg;

    msg = nlmsg_alloc();

    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, sk->family_req, 0, NLM_F_REQUEST, cmd, 1);
    return msg;
}

void seg6_set_callback(struct seg6_sock *sk, int cmd, void (*callback)(struct seg6_sock *, struct nlattr **))
{
    sk->callbacks[cmd*2+1] = callback;
}

static int nl_recv_cb(struct nl_msg *msg, void *arg)
{
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *gnlh = nlmsg_data(nlh);
    struct nlattr *attrs[SEG6_ATTR_MAX + 1];
    struct seg6_sock *sk;
    void (*callback)(struct seg6_sock *, struct nlattr **);

    sk = (struct seg6_sock *)arg;

    if (genlmsg_parse(nlh, 0, attrs, SEG6_ATTR_MAX, seg6_genl_policy)) {
        perror("genlmsg_parse");
        return NL_SKIP;
    }

    callback = sk->callbacks[gnlh->cmd*2+1];
    if (callback)
        callback(sk, attrs);

    return NL_SKIP;
}

static int __seg6_recv(struct seg6_sock *sk, struct nl_cb *cb)
{
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, nl_recv_cb, sk);
    return nl_recvmsgs(sk->nl_sk, cb);
}

static int nl_send_error(struct sockaddr_nl *nla __unused, struct nlmsgerr *err, void *arg)
{
    int *error = (int *)arg;

    *error = err->error;
    return NL_SKIP;
}

static int nl_send_ack(struct nl_msg *msg __unused, void *arg)
{
    int *error = (int *)arg;

    *error = 0;
    return NL_STOP;
}

static int nl_send_and_recv(struct seg6_sock *sk, struct nl_msg *msg, int keepalive)
{
    struct nl_cb *cb;
    int err = -ENOMEM;

    cb = nl_cb_clone(nl_socket_get_cb(sk->nl_sk));
    if (!cb)
        goto out;

    err = nl_send_auto_complete(sk->nl_sk, msg);
    if (err < 0)
        goto out;

    err = 1;

    nl_cb_err(cb, NL_CB_CUSTOM, nl_send_error, &err);
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, nl_send_ack, &err);

    while (err > 0 || keepalive)
        __seg6_recv(sk, cb);

out:
    nl_cb_put(cb);
    nlmsg_free(msg);
    return err ? -(errno = -err) : 0;
}

int seg6_send_msg(struct seg6_sock *sk, struct nl_msg *msg, int keepalive)
{
    return nl_send_and_recv(sk, msg, keepalive);
}
