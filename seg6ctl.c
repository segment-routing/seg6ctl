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
#include "seg6.h"

void usage(char *) __attribute__((noreturn));

void usage(char *av0)
{
    fprintf(stderr, "Usage: %s [-s|--show]\n"
                    "\t\t[-f|--flush]\n"
                    "\t\t[-a SEGMENTS|--add SEGMENTS]\n"
                    "\t\t[-d|--delete]\n"
                    "\t\t[-p PREFIX/LEN|--prefix PREFIX/LEN]\n"
                    "\t\t[--cleanup]\n"
                    "\t\t[-m KEYID|--hmackeyid KEYID]\n"
                    "\t\t[-i SEGLISTID|--id SEGLISTID]\n"
                    "\t\t[--set-hmac ALGO]\n"
                    "\t\t[--dump-hmac]\n"
                    "\t\t[--bind-sid SEGMENT]\n"
                    "\t\t[--nexthop SEGMENT]\n"
                    "\t\t[--dump-bind]\n"
                    "\t\t[--flush-bind]\n"
                    "\t\t[--bind-op OPERATION]\n"
                    "\t\t[--egress-present]\n", av0);
    exit(1);
}

int process_addseg(struct seg6_sock *sk, struct nlmsghdr *msg, char *ddst, int id, char *segs, int cleanup, uint8_t hmackeyid, int egress)
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
    nlmem_nla_put(sk->nlm_sk, msg, SEG6_ATTR_DST, sizeof(struct in6_addr), &daddr);
    nlmem_nla_put_u32(sk->nlm_sk, msg, SEG6_ATTR_DSTLEN, atoi(len));
    nlmem_nla_put_u16(sk->nlm_sk, msg, SEG6_ATTR_SEGLISTID, id);
    nlmem_nla_put_u32(sk->nlm_sk, msg, SEG6_ATTR_FLAGS, ((cleanup & 0x1) << 3) | ((egress & 0x1) << 4));
    nlmem_nla_put_u8(sk->nlm_sk, msg, SEG6_ATTR_HMACKEYID, hmackeyid);

    for (i = 0; s[i]; s[i] == ',' ? i++ : *s++);
    seg_len = i+1+!egress;

    nlmem_nla_put_u32(sk->nlm_sk, msg, SEG6_ATTR_SEGLEN, seg_len);

    segments = calloc(seg_len, sizeof(struct in6_addr));

    i = 0;
    seg = strtok(segs, ",");
    do {
        inet_pton(AF_INET6, seg, &segments[i]);
        i++;
    } while ((seg = strtok(NULL, ",")));

    nlmem_nla_put(sk->nlm_sk, msg, SEG6_ATTR_SEGMENTS, seg_len*sizeof(struct in6_addr), segments);

    free(segments);
    return 0;
}

int process_delseg(struct seg6_sock *sk, struct nlmsghdr *msg, char *ddst, int id)
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

    nlmem_nla_put(sk->nlm_sk, msg, SEG6_ATTR_DST, sizeof(struct in6_addr), &daddr);
    nlmem_nla_put_u32(sk->nlm_sk, msg, SEG6_ATTR_DSTLEN, atoi(len));
    nlmem_nla_put_u16(sk->nlm_sk, msg, SEG6_ATTR_SEGLISTID, id);

    return 0;
}

static void parse_dump(struct seg6_sock *sk __unused, struct nlattr **attr)
{
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

    if (!attr || !attr[SEG6_ATTR_SEGINFO])
        return;

    nla_parse_nested(a, SEG6_ATTR_MAX, attr[SEG6_ATTR_SEGINFO], NULL);
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
        printf("%s%c", (i == seg_len - 1 && (!(flags & 0x10))) ? "<dest>" : ip6, (i == seg_len - 1) ? 0 : ' ');
    }
    printf("] id %d hmac 0x%x %s\n", seg_id, hmackeyid, (flags & 0x8) ? "cleanup " : "");
    free(segments);
}

static void parse_dumphmac(struct seg6_sock *sk __unused, struct nlattr **attr)
{
    struct nlattr *a[SEG6_ATTR_MAX + 1];
    int slen, algid, hmackey;
    char secret[64];

    if (!attr || !attr[SEG6_ATTR_HMACINFO])
        return;

    memset(secret, 0, 64);

    nla_parse_nested(a, SEG6_ATTR_MAX, attr[SEG6_ATTR_HMACINFO], NULL);
    slen = nla_get_u8(a[SEG6_ATTR_SECRETLEN]);
    memcpy(secret, nla_data(a[SEG6_ATTR_SECRET]), slen);
    algid = nla_get_u8(a[SEG6_ATTR_ALGID]);
    hmackey = nla_get_u8(a[SEG6_ATTR_HMACKEYID]);

    printf("hmac 0x%x algo %d secret \"%s\"\n", hmackey, algid, secret);
}

static void parse_dumpbind(struct seg6_sock *sk __unused, struct nlattr **attr)
{
    struct nlattr *a[SEG6_ATTR_MAX + 1];
    struct in6_addr dst, nexthop;
    char ip6[40], ip6nh[40];
    int bop;
    uint32_t nlpid = 0;

    if (!attr || !attr[SEG6_ATTR_BINDINFO])
        return;

    nla_parse_nested(a, SEG6_ATTR_MAX, attr[SEG6_ATTR_BINDINFO], NULL);
    bop = nla_get_u8(a[SEG6_ATTR_BIND_OP]);
    memcpy(&dst, nla_data(a[SEG6_ATTR_DST]), sizeof(struct in6_addr));

    inet_ntop(AF_INET6, &dst, ip6, 40);
    printf("binding-sid %s op %d", ip6, bop);

    if (bop == SEG6_BIND_ROUTE) {
        memcpy(&nexthop, nla_data(a[SEG6_ATTR_BIND_DATA]), sizeof(struct in6_addr));
        inet_ntop(AF_INET6, &nexthop, ip6nh, 40);
        printf(" next-hop %s\n", ip6nh);
    }
    if (bop == SEG6_BIND_SERVICE) {
        memcpy(&nlpid, nla_data(a[SEG6_ATTR_BIND_DATA]), sizeof(uint32_t));
        printf(" pid %u\n", nlpid);
    }
}

int main(int ac, char **av)
{
    struct seg6_sock *sk;
    struct nlmsghdr *msg;
    int c;
    char *pass;
    struct in6_addr in6;
    static struct {
        uint16_t id;
        int cleanup;
        uint8_t hmackeyid;
        char *prefix;
        char *segments;
        int algo;
        char *binding_sid;
        char *nexthop;
        int bind_op;
        int egress;
    } opts;
    int op = 0;
    int ret;
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
            {"hmackeyid", required_argument, 0, 'm'},
            {"id",      required_argument,  0, 'i'},
            {"set-hmac", required_argument, 0, 0 },
            {"dump-hmac", no_argument, 0, 0 },
            {"bind-sid", required_argument, 0, 0 },
            {"bind-op", required_argument, 0, 0 },
            {"nexthop", required_argument, 0, 0 },
            {"dump-bind", no_argument, 0, 0 },
            {"flush-bind", no_argument, 0, 0 },
            {"egress-present", no_argument, &opts.egress, 1},
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
            } else if (!strcmp(long_options[option_index].name, "bind-op")) {
                opts.bind_op = atoi(optarg);
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

    sk = seg6_socket_create(getpagesize(), 64);
    if (!sk) {
        fprintf(stderr, "Cannot create netlink socket. Are you sure to be root ?\n");
        return 1;
    }

    seg6_set_callback(sk, SEG6_CMD_DUMP, parse_dump);
    seg6_set_callback(sk, SEG6_CMD_DUMPHMAC, parse_dumphmac);
    seg6_set_callback(sk, SEG6_CMD_DUMPBIND, parse_dumpbind);

    switch (op) {
    case OP_DUMP:
        msg = seg6_new_msg(sk, SEG6_CMD_DUMP);
        break;
    case OP_FLUSH:
        msg = seg6_new_msg(sk, SEG6_CMD_FLUSH);
        break;
    case OP_ADD:
        if (!opts.prefix) {
            fprintf(stderr, "Missing prefix for ADD operation\n");
            return 1;
        }

        msg = seg6_new_msg(sk, SEG6_CMD_ADDSEG);
        if (process_addseg(sk, msg, opts.prefix, opts.id, opts.segments, opts.cleanup, opts.hmackeyid, opts.egress))
            return 1;
        break;
    case OP_DEL:
        if (!opts.prefix) {
            fprintf(stderr, "Missing prefix for DEL operation\n");
            return 1;
        }

        msg = seg6_new_msg(sk, SEG6_CMD_DELSEG);
        if (process_delseg(sk, msg, opts.prefix, opts.id))
            return 1;
        break;
    case OP_DUMPHMAC:
        msg = seg6_new_msg(sk, SEG6_CMD_DUMPHMAC);
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

        msg = seg6_new_msg(sk, SEG6_CMD_SETHMAC);
        nlmem_nla_put_u8(sk->nlm_sk, msg, SEG6_ATTR_HMACKEYID, opts.hmackeyid);
        nlmem_nla_put_u8(sk->nlm_sk, msg, SEG6_ATTR_ALGID, opts.algo);
        nlmem_nla_put_u8(sk->nlm_sk, msg, SEG6_ATTR_SECRETLEN, strlen(pass));
        if (strlen(pass))
            nlmem_nla_put(sk->nlm_sk, msg, SEG6_ATTR_SECRET, strlen(pass), pass);
        break;
    case OP_BINDSID:
        if (!opts.bind_op) {
            fprintf(stderr, "Missing binding operation\n");
            return 1;
        }

        if (!opts.nexthop && opts.bind_op == SEG6_BIND_ROUTE) {
            fprintf(stderr, "Missing nexthop for BINDSID operation\n");
            return 1;
        }

        msg = seg6_new_msg(sk, SEG6_CMD_ADDBIND);
        inet_pton(AF_INET6, opts.binding_sid, &in6);
        nlmem_nla_put(sk->nlm_sk, msg, SEG6_ATTR_DST, sizeof(struct in6_addr), &in6);
        nlmem_nla_put_u8(sk->nlm_sk, msg, SEG6_ATTR_BIND_OP, opts.bind_op);

        switch (opts.bind_op) {
            case SEG6_BIND_ROUTE:
                inet_pton(AF_INET6, opts.nexthop, &in6);
                nlmem_nla_put(sk->nlm_sk, msg, SEG6_ATTR_BIND_DATA, sizeof(struct in6_addr), &in6);
                nlmem_nla_put_u32(sk->nlm_sk, msg, SEG6_ATTR_BIND_DATALEN, sizeof(struct in6_addr));
                break;
            case SEG6_BIND_SERVICE:
                nlmem_nla_put(sk->nlm_sk, msg, SEG6_ATTR_BIND_DATA, 0, NULL);
                nlmem_nla_put_u32(sk->nlm_sk, msg, SEG6_ATTR_BIND_DATALEN, 0);
                break;
            default:
                fprintf(stderr, "Unknown binding operation\n");
                return 1;
        }
        break;
    case OP_DUMPBIND:
        msg = seg6_new_msg(sk, SEG6_CMD_DUMPBIND);
        break;
    case OP_FLUSHBIND:
        msg = seg6_new_msg(sk, SEG6_CMD_FLUSHBIND);
        break;
    default:
        usage(av[0]);
    }

    ret = seg6_send_and_recv(sk, msg, NULL);
    if (ret)
        fprintf(stderr, "seg6_send_and_recv(): %s\n", strerror(-ret));

    seg6_socket_destroy(sk);

    return 0;
}
