// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/stddef.h>
#include <linux/tcp.h>
#include <sys/socket.h>
#include <bpf/bpf_helpers.h>
#include "bpf_tcp_helpers.h"

char _license[] SEC("license") = "GPL";

struct tcp_rcv_ssthresh_storage {
	__u32 rcv_wnd;
	__u32 rcv_ssthresh;
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct tcp_rcv_ssthresh_storage);
} socket_storage_map SEC(".maps");

static void set_socket_opts(struct bpf_sock_ops *ctx, int rcv_ssthresh)
{
	int rcv_buf = rcv_ssthresh * 2;

	bpf_setsockopt(ctx, SOL_SOCKET, SO_RCVBUF, &rcv_buf, sizeof(rcv_buf));

	bpf_setsockopt(ctx, SOL_TCP, TCP_BPF_RCV_SSTHRESH,
		       &rcv_ssthresh, sizeof(rcv_ssthresh));

	bpf_sock_ops_cb_flags_set(ctx, ctx->bpf_sock_ops_cb_flags |
				  BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
}

SEC("sockops")
int _sockops(struct bpf_sock_ops *ctx)
{
	struct tcp_rcv_ssthresh_storage *storage;
	struct bpf_sock *sk;
	struct tcp_sock *tp;

	sk = ctx->sk;
	if (!sk)
		return 1;

	storage = bpf_sk_storage_get(&socket_storage_map, sk, 0,
				     BPF_SK_STORAGE_GET_F_CREATE);
	if (!storage)
		return 1;

	switch (ctx->op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		set_socket_opts(ctx, 80000);
		break;
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		set_socket_opts(ctx, 90000);
		break;
	case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
		/* We need to set something to get into the next op. */
		bpf_reserve_hdr_opt(ctx, 8, 0);
		break;
	case BPF_SOCK_OPS_WRITE_HDR_OPT_CB:
		/* The first ack from the client is processed here. */
		break;
	default:
		return 1;
	}

	tp = bpf_skc_to_tcp_sock(sk);

	if (tp) {
		storage->rcv_wnd = tp->rcv_wnd;
		storage->rcv_ssthresh = tp->rcv_ssthresh;
	}

	return 1;
}
