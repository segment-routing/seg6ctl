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
    fprintf(stderr, "Usage: %s\n"
                    "\t\t[-m KEYID|--hmackeyid KEYID]\n"
                    "\t\t[--set-hmac ALGO]\n"
                    "\t\t[--dump-hmac]\n"
                    "\t\t[--bind-sid SEGMENT]\n"
                    "\t\t[--nexthop SEGMENT]\n"
                    "\t\t[--dump-bind]\n"
                    "\t\t[--flush-bind]\n"
                    "\t\t[--bind-op OPERATION]\n"
                    "\t\t[--set-tunsrc ADDR]\n", av0);
    exit(1);
}

static void parse_dumphmac(struct seg6_sock *sk __unused, struct nlattr **attr,
        struct nlmsghdr *nlh __unused)
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

static void parse_dumpbind(struct seg6_sock *sk __unused, struct nlattr **attr,
        struct nlmsghdr *nlh __unused)
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
        uint8_t hmackeyid;
        int algo;
        char *binding_sid;
        char *nexthop;
        int bind_op;
        char *tunsrc;
    } opts;
    int op = 0;
    int ret;
#define OP_SETHMAC  6
#define OP_DUMPHMAC 7
#define OP_BINDSID  8
#define OP_DUMPBIND 9
#define OP_FLUSHBIND 10
#define OP_SETTUNSRC 11

    static struct option long_options[] =
        {
            {"hmackeyid", required_argument, 0, 'm'},
            {"set-hmac", required_argument, 0, 0 },
            {"dump-hmac", no_argument, 0, 0 },
            {"bind-sid", required_argument, 0, 0 },
            {"bind-op", required_argument, 0, 0 },
            {"nexthop", required_argument, 0, 0 },
            {"dump-bind", no_argument, 0, 0 },
            {"flush-bind", no_argument, 0, 0 },
            {"set-tunsrc", required_argument, 0, 0},
            {0, 0, 0, 0}
        };
    int option_index = 0;

    memset(&opts, 0, sizeof(opts));

    while ((c = getopt_long(ac, av, "m:", long_options, &option_index)) != -1) {
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
            } else if (!strcmp(long_options[option_index].name, "set-tunsrc")) {
                op = OP_SETTUNSRC;
                opts.tunsrc = optarg;
            }
            break;
        case 'm':
            opts.hmackeyid = atoi(optarg);
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

    seg6_set_callback(sk, SEG6_CMD_DUMPHMAC, parse_dumphmac);
    seg6_set_callback(sk, SEG6_CMD_DUMPBIND, parse_dumpbind);

    switch (op) {
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
    case OP_SETTUNSRC:
        msg = seg6_new_msg(sk, SEG6_CMD_SET_TUNSRC);
        inet_pton(AF_INET6, opts.tunsrc, &in6);
        nlmem_nla_put(sk->nlm_sk, msg, SEG6_ATTR_DST, sizeof(struct in6_addr), &in6);
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
