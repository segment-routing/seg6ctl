/*
 *  seg6ctl.c
 *
 *  Userland tool to control SR-IPv6 structures within the Linux kernel
 *
 *  Copyright (C) 2014 David Lebrun (david.lebrun@uclouvain.be), UCLouvain
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
*/

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

#define __unused __attribute__((unused))

void usage(char *) __attribute__((noreturn));

enum {
    SEG6_ATTR_UNSPEC,
    SEG6_ATTR_DST,
    SEG6_ATTR_DSTLEN,
    SEG6_ATTR_SEGLISTID,
    SEG6_ATTR_FLAGS,
    SEG6_ATTR_HMACKEYID,
    SEG6_ATTR_SEGMENTS,
    SEG6_ATTR_SEGLEN,
    SEG6_ATTR_SEGINFO,
    SEG6_ATTR_SECRET,
    SEG6_ATTR_SECRETLEN,
    SEG6_ATTR_ALGID,
    SEG6_ATTR_HMACINFO,
    SEG6_ATTR_BIND_NEXTHOP,
    SEG6_ATTR_BINDINFO,
    __SEG6_ATTR_MAX,
};

#define SEG6_ATTR_MAX (__SEG6_ATTR_MAX - 1)

enum {
    SEG6_CMD_UNSPEC,
    SEG6_CMD_ADDSEG,
    SEG6_CMD_DELSEG,
    SEG6_CMD_FLUSH,
    SEG6_CMD_DUMP,
    SEG6_CMD_SETHMAC,
    SEG6_CMD_DUMPHMAC,
    SEG6_CMD_ADDBIND,
    SEG6_CMD_DELBIND,
    SEG6_CMD_FLUSHBIND,
    SEG6_CMD_DUMPBIND,
    __SEG6_CMD_MAX,
};

#define SEG6_CMD_MAX (__SEG6_CMD_MAX - 1)

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
    [SEG6_ATTR_BIND_NEXTHOP] = { .type = NLA_UNSPEC, .maxlen = sizeof(struct in6_addr) },
    [SEG6_ATTR_BINDINFO]    = { .type = NLA_NESTED, },
};

void usage(char *av0)
{
    fprintf(stderr, "Usage: %s [-s|--show]\n"
                    "\t\t[-f|--flush]\n"
                    "\t\t[-a SEGMENTS|--add SEGMENTS]\n"
                    "\t\t[-d|--delete]\n"
                    "\t\t[-p PREFIX/LEN|--prefix PREFIX/LEN]\n"
                    "\t\t[--cleanup]\n"
                    "\t\t[--tunnel]\n"
                    "\t\t[-m KEYID|--hmackeyid KEYID]\n"
                    "\t\t[-i SEGLISTID|--id SEGLISTID]\n"
                    "\t\t[--set-hmac ALGO]\n"
                    "\t\t[--dump-hmac]\n"
                    "\t\t[--bind-sid SEGMENT]\n"
                    "\t\t[--nexthop SEGMENT]\n"
                    "\t\t[--dump-bind]\n"
                    "\t\t[--flush-bind]\n", av0);
    exit(1);
}

int process_addseg(struct nl_msg *msg, char *ddst, int id, char *segs, int cleanup, uint8_t hmackeyid, int tunnel)
{
    char *dst, *len, *seg;
    int i, seg_len;
    struct in6_addr daddr;
    struct in6_addr *segments;
    char *s = segs;

    dst = strtok(ddst, "/");
    len = strtok(NULL, "/");

    if (!len || !*len) {
        fprintf(stderr, "Missing prefix length\n");
        return 1;
    }

    inet_pton(AF_INET6, dst, &daddr);
    nla_put(msg, SEG6_ATTR_DST, sizeof(struct in6_addr), &daddr);
    nla_put_u32(msg, SEG6_ATTR_DSTLEN, atoi(len));
    nla_put_u16(msg, SEG6_ATTR_SEGLISTID, id);
    nla_put_u32(msg, SEG6_ATTR_FLAGS, ((cleanup & 0x1) << 3) | ((tunnel & 0x1) << 1));
    nla_put_u8(msg, SEG6_ATTR_HMACKEYID, hmackeyid);

    for (i = 0; s[i]; s[i] == ',' ? i++ : *s++);
    seg_len = i+1;

    nla_put_u32(msg, SEG6_ATTR_SEGLEN, seg_len);

    segments = malloc(sizeof(struct in6_addr)*seg_len);

    i = 0;
    seg = strtok(segs, ",");
    do {
        memset(&segments[i].s6_addr, 0, 16);
        inet_pton(AF_INET6, seg, &segments[i]);
        i++;
    } while ((seg = strtok(NULL, ",")));

    nla_put(msg, SEG6_ATTR_SEGMENTS, seg_len*sizeof(struct in6_addr), segments);

    free(segments);
    return 0;
}

int process_delseg(struct nl_msg *msg, char *ddst, int id)
{
    char *dst, *len;
    struct in6_addr daddr;

    dst = strtok(ddst, "/");
    len = strtok(NULL, "/");

    if (!len || !*len) {
        fprintf(stderr, "Missing prefix length\n");
        return 1;
    }

    inet_pton(AF_INET6, dst, &daddr);

    nla_put(msg, SEG6_ATTR_DST, sizeof(struct in6_addr), &daddr);
    nla_put_u32(msg, SEG6_ATTR_DSTLEN, atoi(len));
    nla_put_u16(msg, SEG6_ATTR_SEGLISTID, id);

    return 0;
}

static void parse_dump(struct nlattr *attr)
{
    static struct nla_policy uspace_pol[SEG6_ATTR_MAX + 1] =  {
        [SEG6_ATTR_DST] = { .type = NLA_UNSPEC, .maxlen = sizeof(struct in6_addr) },
        [SEG6_ATTR_SEGMENTS] = { .type = NLA_UNSPEC, },
    };

    struct nlattr *a[SEG6_ATTR_MAX + 1];

    char ip6[40];
    struct in6_addr dst;
    int dst_len;
    int seg_id;
    int flags;
    int hmackeyid;
    struct in6_addr *segments;
    int seg_len;
    int i;

    if (!attr)
        return;

    nla_parse_nested(a, SEG6_ATTR_MAX, attr, uspace_pol);
    memcpy(&dst, nla_data(a[SEG6_ATTR_DST]), sizeof(struct in6_addr));
    dst_len = nla_get_u32(a[SEG6_ATTR_DSTLEN]);
    seg_id = nla_get_u16(a[SEG6_ATTR_SEGLISTID]);
    flags = nla_get_u32(a[SEG6_ATTR_FLAGS]);
    hmackeyid = nla_get_u8(a[SEG6_ATTR_HMACKEYID]);
    seg_len = nla_get_u32(a[SEG6_ATTR_SEGLEN]);

    segments = malloc(seg_len*sizeof(struct in6_addr));
    memcpy(segments, nla_data(a[SEG6_ATTR_SEGMENTS]), seg_len*sizeof(struct in6_addr));

    inet_ntop(AF_INET6, &dst, ip6, 40);

    printf("%s/%d via %d segs [", ip6, dst_len, seg_len);
    for (i = 0; i < seg_len; i++) {
        inet_ntop(AF_INET6, &segments[i], ip6, 40);
        printf("%s%c", ip6, (i == seg_len - 1) ? 0 : ' ');
    }
    printf("] id %d hmac 0x%x %s%s\n", seg_id, hmackeyid, (flags & 0x8) ? "cleanup " : "", (flags & 0x2) ? "tunnel" : "");
    free(segments);
}

static void parse_dumphmac(struct nlattr *attr)
{
    static struct nla_policy uspace_pol[SEG6_ATTR_MAX + 1] = {
        [SEG6_ATTR_SECRET] = { .type = NLA_UNSPEC, .maxlen = 64 },
    };

    struct nlattr *a[SEG6_ATTR_MAX + 1];
    int slen, algid, hmackey;
    char secret[64];

    if (!attr)
        return;

    memset(secret, 0, 64);

    nla_parse_nested(a, SEG6_ATTR_MAX, attr, uspace_pol);
    slen = nla_get_u8(a[SEG6_ATTR_SECRETLEN]);
    memcpy(secret, nla_data(a[SEG6_ATTR_SECRET]), slen);
    algid = nla_get_u8(a[SEG6_ATTR_ALGID]);
    hmackey = nla_get_u8(a[SEG6_ATTR_HMACKEYID]);

    printf("hmac 0x%x algo %d secret \"%s\"\n", hmackey, algid, secret);
}

static void parse_dumpbind(struct nlattr *attr)
{
    static struct nla_policy uspace_pol[SEG6_ATTR_MAX + 1] = {
        [SEG6_ATTR_DST] = { .type = NLA_UNSPEC, .maxlen = sizeof(struct in6_addr) },
        [SEG6_ATTR_BIND_NEXTHOP] = { .type = NLA_UNSPEC, .maxlen = sizeof(struct in6_addr) },
    };

    struct nlattr *a[SEG6_ATTR_MAX + 1];
    struct in6_addr dst, nexthop;
    char ip6[40], ip6nh[40];

    if (!attr)
        return;

    nla_parse_nested(a, SEG6_ATTR_MAX, attr, uspace_pol);
    memcpy(&dst, nla_data(a[SEG6_ATTR_DST]), sizeof(struct in6_addr));
    memcpy(&nexthop, nla_data(a[SEG6_ATTR_BIND_NEXTHOP]), sizeof(struct in6_addr));

    inet_ntop(AF_INET6, &dst, ip6, 40);
    inet_ntop(AF_INET6, &nexthop, ip6nh, 40);

    printf("binding-sid %s next-hop %s\n", ip6, ip6nh);
}

static int nl_recv_cb(struct nl_msg *msg, void *arg __unused)
{
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *gnlh = nlmsg_data(nlh);
    struct nlattr *attrs[SEG6_ATTR_MAX + 1];

    if (genlmsg_parse(nlh, 0, attrs, SEG6_ATTR_MAX, seg6_genl_policy)) {
        fprintf(stderr, "Unable to parse netlink message\n");
        return NL_SKIP;
    }

    if (gnlh->cmd == SEG6_CMD_DUMP)
        parse_dump(attrs[SEG6_ATTR_SEGINFO]);

    if (gnlh->cmd == SEG6_CMD_DUMPHMAC)
        parse_dumphmac(attrs[SEG6_ATTR_HMACINFO]);

    if (gnlh->cmd == SEG6_CMD_DUMPBIND)
        parse_dumpbind(attrs[SEG6_ATTR_BINDINFO]);

    return NL_SKIP;
}

static int __seg6_recv(struct nl_sock *sk, struct nl_cb *cb)
{
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, nl_recv_cb, NULL);
    return nl_recvmsgs(sk, cb);
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

static int nl_send_and_recv(struct nl_sock *sk, struct nl_msg *msg)
{
    struct nl_cb *cb;
    int err = -ENOMEM;

    cb = nl_cb_clone(nl_socket_get_cb(sk));
    if (!cb)
        goto out;

    err = nl_send_auto_complete(sk, msg);
    if (err < 0)
        goto out;

    err = 1;

    nl_cb_err(cb, NL_CB_CUSTOM, nl_send_error, &err);
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, nl_send_ack, &err);

    while (err > 0)
        __seg6_recv(sk, cb);

out:
    nl_cb_put(cb);
    nlmsg_free(msg);
    return err ? -(errno = -err) : 0;
}

int main(int ac, char **av)
{
    /* ./seg6ctl dump
     *           flush
     *           add dst/len id segment1,segment2,...,segmentN [cleanup] [hmac HMACKEYID]
     *           del dst/len [id]
     */

    struct nl_sock *nl_sk;
    struct nl_msg *msg;
    int family_req;
    int c;
    char *pass;
    struct in6_addr in6;
    static struct {
        uint16_t id;
        int cleanup;
        int tunnel;
        uint8_t hmackeyid;
        char *prefix;
        char *segments;
        int algo;
        char *binding_sid;
        char *nexthop;
    } opts;
    int op = 0;
#define OP_DUMP     1
#define OP_FLUSH    2
#define OP_ADD      4
#define OP_DEL      5
#define OP_SETHMAC  6
#define OP_DUMPHMAC 7
#define OP_BINDSID  8
#define OP_DUMPBIND 9
#define OP_FLUSHBIND 10

    static struct option long_options[] = 
        {
            {"show",    no_argument,        0, 's'},
            {"flush",   no_argument,        0, 'f'},
            {"add",     required_argument,  0, 'a'},
            {"del",     no_argument,        0, 'd'},
            {"prefix",  required_argument,  0, 'p'},
            {"cleanup", no_argument,        &opts.cleanup, 1},
            {"tunnel", no_argument, &opts.tunnel, 1},
            {"hmackeyid", required_argument, 0, 'm'},
            {"id",      required_argument,  0, 'i'},
            {"set-hmac", required_argument, 0, 0 },
            {"dump-hmac", no_argument, 0, 0 },
            {"bind-sid", required_argument, 0, 0 },
            {"nexthop", required_argument, 0, 0 },
            {"dump-bind", no_argument, 0, 0 },
            {"flush-bind", no_argument, 0, 0 },
            {0, 0, 0, 0}
        };
    int option_index = 0;

    memset(&opts, 0, sizeof(opts));

    while ((c = getopt_long(ac, av, "sfa:dp:m:i:", long_options, &option_index)) != -1) {
        switch (c) {
        case 0:
            if (!strcmp(long_options[option_index].name, "set-hmac")) {
                op = OP_SETHMAC;
                opts.algo = atoi(optarg);
            } else if (!strcmp(long_options[option_index].name, "dump-hmac")) {
                op = OP_DUMPHMAC;
            } else if (!strcmp(long_options[option_index].name, "bind-sid")) {
                op = OP_BINDSID;
                opts.binding_sid = optarg;
            } else if (!strcmp(long_options[option_index].name, "nexthop")) {
                opts.nexthop = optarg;
            } else if (!strcmp(long_options[option_index].name, "dump-bind")) {
                op = OP_DUMPBIND;
            } else if (!strcmp(long_options[option_index].name, "flush-bind")) {
                op = OP_FLUSHBIND;
            }
            break;
        case 's':
            op = OP_DUMP;
            break;
        case 'f':
            op = OP_FLUSH;
            break;
        case 'a':
            op = OP_ADD;
            opts.segments = optarg;
            break;
        case 'd':
            op = OP_DEL;
            break;
        case 'p':
            opts.prefix = optarg;
            break;
        case 'm':
            opts.hmackeyid = atoi(optarg);
            break;
        case 'i':
            opts.id = atoi(optarg);
            break;
        case '?':
            break;
        default:
            abort();
        }
    }

    if (op == 0)
        usage(av[0]);

    nl_sk = nl_socket_alloc();
    if (!nl_sk) {
        perror("nl_socket_alloc");
        return 1;
    }

    if (genl_connect(nl_sk)) {
        perror("genl_connect");
        return 1;
    }

    family_req = genl_ctrl_resolve(nl_sk, "SEG6");

    nl_socket_disable_seq_check(nl_sk);

    msg = nlmsg_alloc();
    if (!msg) {
        perror("nlmsg_alloc");
        return 1;
    }


    switch (op) {
    case OP_DUMP:
        genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_req, 0, NLM_F_REQUEST, SEG6_CMD_DUMP, 1);
        break;
    case OP_FLUSH:
        genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_req, 0, NLM_F_REQUEST, SEG6_CMD_FLUSH, 1);
        break;
    case OP_ADD:
        if (!opts.prefix) {
            fprintf(stderr, "Missing prefix for ADD operation\n");
            return 1;
        }

        genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_req, 0, NLM_F_REQUEST, SEG6_CMD_ADDSEG, 1);
        if (process_addseg(msg, opts.prefix, opts.id, opts.segments, opts.cleanup, opts.hmackeyid, opts.tunnel))
            return 1;
        break;
    case OP_DEL:
        if (!opts.prefix) {
            fprintf(stderr, "Missing prefix for DEL operation\n");
            return 1;
        }

        genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_req, 0, NLM_F_REQUEST, SEG6_CMD_DELSEG, 1);
        if (process_delseg(msg, opts.prefix, opts.id))
            return 1;
        break;
    case OP_DUMPHMAC:
        genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_req, 0, NLM_F_REQUEST, SEG6_CMD_DUMPHMAC, 1);
        break;
    case OP_SETHMAC:
        if (!opts.algo) {
            fprintf(stderr, "Missing hashing algorithm for SETHMAC operation\n");
            return 1;
        }

        if (!opts.hmackeyid) {
            fprintf(stderr, "Missing HMAC key id for SETHMAC operation\n");
            return 1;
        }

        pass = getpass("Enter secret for HMAC key id: ");

        genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_req, 0, NLM_F_REQUEST, SEG6_CMD_SETHMAC, 1);
        nla_put_u8(msg, SEG6_ATTR_HMACKEYID, opts.hmackeyid);
        nla_put_u8(msg, SEG6_ATTR_ALGID, opts.algo);
        nla_put_u8(msg, SEG6_ATTR_SECRETLEN, strlen(pass));
        if (strlen(pass))
            nla_put(msg, SEG6_ATTR_SECRET, strlen(pass), pass);
        break;
    case OP_BINDSID:
        if (!opts.nexthop) {
            fprintf(stderr, "Missing nexthop for BINDSID operation\n");
            return 1;
        }

        genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_req, 0, NLM_F_REQUEST, SEG6_CMD_ADDBIND, 1);
        inet_pton(AF_INET6, opts.binding_sid, &in6);
        nla_put(msg, SEG6_ATTR_DST, sizeof(struct in6_addr), &in6);
        inet_pton(AF_INET6, opts.nexthop, &in6);
        nla_put(msg, SEG6_ATTR_BIND_NEXTHOP, sizeof(struct in6_addr), &in6);
        break;
    case OP_DUMPBIND:
        genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_req, 0, NLM_F_REQUEST, SEG6_CMD_DUMPBIND, 1);
        break;
    case OP_FLUSHBIND:
        genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_req, 0, NLM_F_REQUEST, SEG6_CMD_FLUSHBIND, 1);
        break;
    default:
        usage(av[0]);
    }

    nl_send_and_recv(nl_sk, msg);
    if (errno)
        perror("nl_send_and_recv");

    nl_socket_free(nl_sk);
    return 0;
}
