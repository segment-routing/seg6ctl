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
#include <sys/mman.h>
#include "nlmem.h"

/*
 *  Socket handling
 */

static int resolve_ctrl(int fd, const char *family)
{
    struct {
        struct nlmsghdr n;
        struct genlmsghdr g;
        char buf[4096];
    } nl_req_msg, nl_resp_msg;
    struct nlattr *nl_na;
    struct sockaddr_nl nl_address;
    int rlen;
    struct nlmsgerr *err;

    nl_req_msg.n.nlmsg_type = GENL_ID_CTRL;
    nl_req_msg.n.nlmsg_flags = NLM_F_REQUEST;
    nl_req_msg.n.nlmsg_seq = 0;
    nl_req_msg.n.nlmsg_pid = getpid();
    nl_req_msg.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);

    nl_req_msg.g.cmd = CTRL_CMD_GETFAMILY;
    nl_req_msg.g.version = 0x1;

    nl_na = (struct nlattr *)genlmsg_data(&nl_req_msg.g);
    nl_na->nla_type = CTRL_ATTR_FAMILY_NAME;
    nl_na->nla_len = strlen(family) + 1 + NLA_HDRLEN;
    strcpy(nla_data(nl_na), family);

    nl_req_msg.n.nlmsg_len += NLMSG_ALIGN(nl_na->nla_len);

    memset(&nl_address, 0, sizeof(nl_address));
    nl_address.nl_family = AF_NETLINK;

    rlen = sendto(fd, (char *)&nl_req_msg, nl_req_msg.n.nlmsg_len, 0, (struct sockaddr *)&nl_address, sizeof(nl_address));
    if (rlen != (int)nl_req_msg.n.nlmsg_len) {
        perror("sendto");
        return -1;
    }

    rlen = recv(fd, &nl_resp_msg, sizeof(nl_resp_msg), 0);
    if (rlen < 0) {
        perror("recv");
        return -1;
    }

    if (!NLMSG_OK((&nl_resp_msg.n), rlen)) {
        fprintf(stderr, "resolve_ctrl: invalid message (length: %d)\n", rlen);
        return -1;
    }

    if (nl_resp_msg.n.nlmsg_type == NLMSG_ERROR) {
        fprintf(stderr, "resolve_ctrl: error received\n");
        err = nlmsg_data(&nl_resp_msg.n);
        fprintf(stderr, "resolve_ctrl: error is %d\n", err->error);
        return -1;
    }

    nl_na = (struct nlattr *)genlmsg_data(&nl_resp_msg.g);
    nl_na = (struct nlattr *)((char *)nl_na + NLA_ALIGN(nl_na->nla_len));

    if (nl_na->nla_type == CTRL_ATTR_FAMILY_ID)
        return *(uint16_t *)nla_data(nl_na);

    fprintf(stderr, "resolve_ctrl: no family\n");
    return -1;
}

struct nlmem_sock *nlmem_sock_create(struct nl_mmap_req *req, const char *family)
{
    struct nlmem_sock *sk;
    int family_req;
    struct sockaddr_nl nl_address;
    unsigned int ring_size;
    void *rx_ring, *tx_ring;
    struct nl_mmap_req req2;

    if (!req) {
        unsigned int block_size = 16 * getpagesize();
        req2.nm_block_size  = block_size;
        req2.nm_block_nr    = 64;
        req2.nm_frame_size  = 16384;
        req2.nm_frame_nr    = 64 * block_size / 16384;
    } else {
        memcpy(&req2, req, sizeof(*req));
    }

    sk = malloc(sizeof(*sk));
    memset(sk, 0, sizeof(*sk));

    if ((sk->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC)) < 0) {
        perror("socket");
        goto err;
    }

    memset(&nl_address, 0, sizeof(nl_address));
    nl_address.nl_family = AF_NETLINK;
    nl_address.nl_groups = 0;

    if (bind(sk->fd, (struct sockaddr *)&nl_address, sizeof(nl_address)) < 0) {
        perror("bind");
        goto err_close;
    }

    family_req = resolve_ctrl(sk->fd, family);

    if (family_req == -1) {
        fprintf(stderr, "resolve_ctrl: Unknown requested family\n");
        goto err_close;
    }

    sk->family_req = family_req;

    if (setsockopt(sk->fd, SOL_NETLINK, NETLINK_RX_RING, &req2, sizeof(req2)) < 0) {
        perror("setsockopt");
        goto err_close;
    }

    if (setsockopt(sk->fd, SOL_NETLINK, NETLINK_TX_RING, &req2, sizeof(req2)) < 0) {
        perror("setsockopt");
        goto err_close;
    }

    ring_size = req2.nm_block_nr * req2.nm_block_size;

    rx_ring = mmap(NULL, 2 * ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, sk->fd, 0);
    if ((long)rx_ring == -1L) {
        perror("mmap");
        goto err_close;
    }

    tx_ring = rx_ring + ring_size;

    sk->frame_size = req2.nm_frame_size;
    sk->ring_size = ring_size;
    sk->rx_ring = rx_ring;
    sk->tx_ring = tx_ring;

    sk->delayed_release = 0;

    return sk;

err_close:
    close(sk->fd);
err:
    free(sk);
    return NULL;
}

void nlmem_sock_destroy(struct nlmem_sock *sk)
{
    munmap(sk->rx_ring, 2 * sk->ring_size);
    close(sk->fd);
    free(sk);
}

/*
 *  Message handling
 */

static void __msg_put(struct nlmsghdr *nlh, uint32_t pid, uint32_t seq, int type, int payload, int flags)
{
    nlh->nlmsg_type = type;
    nlh->nlmsg_flags = flags;
    nlh->nlmsg_pid = pid;
    nlh->nlmsg_seq = seq;
    nlh->nlmsg_len = NLMSG_HDRLEN + NLMSG_ALIGN(payload);
}

struct nlmsghdr *nlmem_msg_create(struct nlmem_sock *sk, int cmd, int flags)
{
    struct nl_mmap_hdr *hdr;
    struct nlmsghdr *nlh;
    struct genlmsghdr ghdr = {
        .cmd = cmd,
        .version = 1,
    };

    hdr = current_tx_frame(sk);
    if (hdr->nm_status != NL_MMAP_STATUS_UNUSED)
        return NULL;

    nlh = (void *)hdr + NL_MMAP_HDRLEN;
    memset(nlh, 0, sizeof(*nlh));

    __msg_put(nlh, NL_AUTO_PID, NL_AUTO_SEQ, sk->family_req, GENL_HDRLEN, flags);
    memcpy(nlmsg_data(nlh), &ghdr, sizeof(ghdr));

    return nlh;
}

struct nlattr *nlmem_nla_create(struct nlmem_sock *sk, struct nlmsghdr *nlh, int attrtype, int attrlen)
{
    struct nlattr *nla;
    unsigned int tlen;

    tlen = nlh->nlmsg_len + nla_total_size(attrlen);

    if (tlen > sk->frame_size - NL_MMAP_HDRLEN)
        return NULL;

    nla = (struct nlattr *)nlmsg_tail(nlh);
    nla->nla_type = attrtype;
    nla->nla_len = nla_attr_size(attrlen);

    if (attrlen)
        memset((char *)nla + nla->nla_len, 0, nla_padlen(attrlen));

    nlh->nlmsg_len = tlen;

    return nla;
}

int nlmem_nla_put(struct nlmem_sock *sk, struct nlmsghdr *nlh, int attrtype, int datalen, const void *data)
{
    struct nlattr *nla;

    nla = nlmem_nla_create(sk, nlh, attrtype, datalen);
    if (!nla)
        return -NLE_NOMEM;

    if (datalen > 0)
        memcpy(nla_data(nla), data, datalen);

    return 0;
}

void nlmem_send_msg(struct nlmem_sock *sk, struct nlmsghdr *nlh)
{
    struct nl_mmap_hdr *hdr;
    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
    };

    hdr = (void *)nlh - NL_MMAP_HDRLEN;

    hdr->nm_len = nlh->nlmsg_len;
    hdr->nm_status = NL_MMAP_STATUS_VALID;

    if (sendto(sk->fd, NULL, 0, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("sendto");
        return;
    }

    advance_tx_frame(sk);
}

#define NLMEM_CB_CALL(cb, type, sk, msg) \
{ \
    int err = cb->cb_set[type](sk, msg, cb->cb_args[type]); \
    switch (err) { \
    case NL_OK: \
        err = 0; \
        break; \
    case NL_SKIP: \
        goto skip; \
    case NL_STOP: \
        goto stop; \
    default: \
        goto stop; \
    } \
}

void nlmem_recv_loop(struct nlmem_sock *sk, struct nlmem_cb *ucb)
{
    struct nl_mmap_hdr *hdr;
    struct nlmsghdr *nlh;
    char *buf;
    int len;
    struct nlmem_cb *cb;

    buf = malloc(sk->frame_size);

    cb = ucb ?: &sk->cb;

    for (;;) {
        //printf("lolo\n");
        struct pollfd pfds[1];

        pfds[0].fd = sk->fd;
        pfds[0].events = POLLIN | POLLERR;
        pfds[0].revents = 0;

        if (poll(pfds, 1, -1) < 0 && errno != EINTR) {
            printf("hihi\n");
            perror("poll");
            break;
        }

        if (pfds[0].revents & POLLERR) {
            printf("hehe\n");
            int error = 0;
            socklen_t errlen = sizeof(error);
            getsockopt(sk->fd, SOL_SOCKET, SO_ERROR, (void *)&error, &errlen);
            fprintf(stderr, "nlmsg_recv_loop: sk->fd in error (%s)", strerror(error));
            break;
        }

        if (!(pfds[0].revents & POLLIN)) {
            printf("haha\n");
            continue;
        }

        for (;;) {
            hdr = current_rx_frame(sk);

            if (hdr->nm_status == NL_MMAP_STATUS_VALID) {
                nlh = (void *)hdr + NL_MMAP_HDRLEN;
                len = hdr->nm_len;

                if (len == 0)
                    goto release;
            } else if (hdr->nm_status == NL_MMAP_STATUS_COPY) {
                len = recv(sk->fd, buf, sk->frame_size, MSG_DONTWAIT);
                if (len <= 0)
                    break;
                nlh = (struct nlmsghdr *)buf;
            } else { // unused or skip
                advance_rx_frame(sk);
                continue;
            }

            while (nlmsg_ok(nlh, len)) {
                if (nlh->nlmsg_type == NLMSG_ERROR) {
                    struct nlmsgerr *e = nlmsg_data(nlh);

                    if (nlh->nlmsg_len < (unsigned)nlmsg_size(sizeof(*e))) {
                        if (cb->cb_set[NLMEM_CB_INVALID]) {
                            NLMEM_CB_CALL(cb, NLMEM_CB_INVALID, sk, nlh);
                        }
                    } else if (e->error) {
                        if (cb->cb_set[NLMEM_CB_ERR]) {
                            NLMEM_CB_CALL(cb, NLMEM_CB_ERR, sk, nlh);
                        } else {
                            goto stop;
                        }
                    } else if (cb->cb_set[NLMEM_CB_ACK]) {
                        NLMEM_CB_CALL(cb, NLMEM_CB_ACK, sk, nlh);
                    }
                } else {
                    if (cb->cb_set[NLMEM_CB_VALID]) {
                            if (sk->delayed_release)
                                hdr->nm_status = NL_MMAP_STATUS_SKIP;
                        NLMEM_CB_CALL(cb, NLMEM_CB_VALID, sk, nlh);
                    }
                }

skip:
                nlh = nlmsg_next(nlh, &len);
            }

release:
            if (!sk->delayed_release)
                hdr->nm_status = NL_MMAP_STATUS_UNUSED;

            advance_rx_frame(sk);
        }
    }

    free(buf);
    return;

/*
 * This label MUST be reached from within the inner for loop
 * before frame release in order to have a valid in-use frame
 */
stop:
    hdr->nm_status = NL_MMAP_STATUS_UNUSED;
    advance_rx_frame(sk);
    free(buf);
}
