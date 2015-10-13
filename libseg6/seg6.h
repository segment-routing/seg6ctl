#ifndef _SEG6_H
#define _SEG6_H

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include <asm/byteorder.h>
#include <stdint.h>

#include "nlmem.h"

#ifndef __u8
#define __u8 uint8_t
#endif

#define __unused __attribute__((unused))

#define SEG6_BIND_NEXT          0   /* aka no-op, classical sr processing */
#define SEG6_BIND_ROUTE         1   /* force route through given next hop */
#define SEG6_BIND_INSERT        2   /* push segments in srh */
#define SEG6_BIND_TRANSLATE     3   /* translate source/dst ? */
#define SEG6_BIND_SERVICE       4   /* send packet to virtual service */
#define SEG6_BIND_OVERRIDE_NEXT 5   /* override next segment (break HMAC) */

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
    SEG6_ATTR_BIND_OP,
    SEG6_ATTR_BIND_DATA,
    SEG6_ATTR_BIND_DATALEN,
    SEG6_ATTR_BINDINFO,
    SEG6_ATTR_PACKET_DATA,
    SEG6_ATTR_PACKET_LEN,
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
    SEG6_CMD_PACKET_IN,
    SEG6_CMD_PACKET_OUT,
    __SEG6_CMD_MAX,
};

#define SEG6_CMD_MAX (__SEG6_CMD_MAX - 1)

struct seg6_sock {
    struct nlmem_sock *nlm_sk;
    void **callbacks;
};

struct seg6_sock *seg6_socket_create(int, int);
void seg6_socket_destroy(struct seg6_sock *);
struct nlmsghdr *seg6_new_msg(struct seg6_sock *, int);
void seg6_set_callback(struct seg6_sock *, int, void (*)(struct seg6_sock *, struct nlattr **));
int seg6_send_and_recv(struct seg6_sock *, struct nlmsghdr *, struct nlmem_cb *);

struct ipv6_sr_hdr {
    __u8        nexthdr;
    __u8        hdrlen;          // 8-octet units
    __u8        type;
    __u8        segments_left;
    __u8        first_segment;

#if defined(__BIG_ENDIAN_BITFIELD)
    __u8        flags : 4,
                pol1_flags : 4;
    __u8        pol2_flags : 4,
                pol3_flags : 4;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    __u8        pol1_flags : 4,
                flags : 4;
    __u8        pol3_flags : 4,
                pol2_flags : 4;
#else
#error "Please fix <asm/byteorder.h>"
#endif

    __u8        hmackeyid;

    struct in6_addr segments[0];
} __attribute__((packed));

#endif
