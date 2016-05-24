#ifndef _NLMEM_H
#define _NLMEM_H

#include <netlink/netlink.h>

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#define NLMEM_CB_VALID      0
#define NLMEM_CB_ACK        1
#define NLMEM_CB_ERR        2
#define NLMEM_CB_INVALID    3
#define __NLMEM_CB_MAX      3

struct nlmem_sock;

typedef int (*nlmem_cb_t)(struct nlmem_sock *, struct nlmsghdr *, void *);

struct nlmem_cb {
    nlmem_cb_t cb_set[__NLMEM_CB_MAX+1];
    void *cb_args[__NLMEM_CB_MAX+1];
};

struct nlmem_sock {
    int fd;
    int family_req;

    unsigned int frame_size;
    unsigned int ring_size;
    void *rx_ring;
    void *tx_ring;

    unsigned int tx_frame_offset;
    unsigned int rx_frame_offset;

    int delayed_release;

    struct nlmem_cb cb;
};

static inline void advance_rx_frame(struct nlmem_sock *sk)
{
    sk->rx_frame_offset = (sk->rx_frame_offset + sk->frame_size) % sk->ring_size;
}

static inline void advance_tx_frame(struct nlmem_sock *sk)
{
    sk->tx_frame_offset = (sk->tx_frame_offset + sk->frame_size) % sk->ring_size;
}

static inline struct nl_mmap_hdr *current_rx_frame(struct nlmem_sock *sk)
{
    return sk->rx_ring + sk->rx_frame_offset;
}

static inline struct nl_mmap_hdr *current_tx_frame(struct nlmem_sock *sk)
{
    return sk->tx_ring + sk->tx_frame_offset;
}

static inline void nlmem_set_cb(struct nlmem_cb *cb, int type, nlmem_cb_t func, void *arg)
{
    cb->cb_set[type] = func;
    cb->cb_args[type] = arg;
}

struct nlmem_sock *nlmem_sock_create(struct nl_mmap_req *, const char *);
void nlmem_sock_destroy(struct nlmem_sock *);
struct nlmsghdr *nlmem_msg_create(struct nlmem_sock *, int, int);
struct nlattr *nlmem_nla_create(struct nlmem_sock *, struct nlmsghdr *, int, int);
int nlmem_nla_put(struct nlmem_sock *, struct nlmsghdr *, int, int, const void *);
void nlmem_send_msg(struct nlmem_sock *, struct nlmsghdr *);
void nlmem_recv_loop(struct nlmem_sock *, struct nlmem_cb *);

static inline int nlmem_nla_put_u8(struct nlmem_sock *sk, struct nlmsghdr *nlh, int attrtype, uint8_t data)
{
    return nlmem_nla_put(sk, nlh, attrtype, sizeof(uint8_t), &data);
}

static inline int nlmem_nla_put_u16(struct nlmem_sock *sk, struct nlmsghdr *nlh, int attrtype, uint16_t data)
{
    return nlmem_nla_put(sk, nlh, attrtype, sizeof(uint16_t), &data);
}

static inline int nlmem_nla_put_u32(struct nlmem_sock *sk, struct nlmsghdr *nlh, int attrtype, uint32_t data)
{
    return nlmem_nla_put(sk, nlh, attrtype, sizeof(uint32_t), &data);
}

#endif
