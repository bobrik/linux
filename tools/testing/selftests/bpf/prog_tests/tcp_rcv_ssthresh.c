// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "cgroup_helpers.h"
#include "network_helpers.h"

struct tcp_rcv_ssthresh_storage {
	__u32 rcv_wnd;
	__u32 rcv_ssthresh;
};

static void send_byte(int fd)
{
	char b = 0x55;

	ASSERT_EQ(write(fd, &b, sizeof(b)), 1, "single byte write");
}

static int wait_for_ack(int fd, int retries)
{
	struct tcp_info info;
	socklen_t optlen;
	int i, err;

	for (i = 0; i < retries; i++) {
		optlen = sizeof(info);
		err = getsockopt(fd, SOL_TCP, TCP_INFO, &info, &optlen);
		if (err < 0) {
			log_err("Failed to lookup TCP stats");
			return err;
		}

		if (info.tcpi_unacked == 0)
			return 0;

		usleep(10);
	}

	log_err("Did not receive ACK: %d", info.tcpi_unacked);
	return -1;
}

static int verify_sstresh(int map_fd, int client_fd, __u32 rcv_ssthresh, __u32 rcv_wnd)
{
	int err;
	int rcv_wnd_min = rcv_wnd - 512;
	int rcv_wnd_max = rcv_wnd + 512;
	struct tcp_rcv_ssthresh_storage val;

	err = bpf_map_lookup_elem(map_fd, &client_fd, &val);

	if (!ASSERT_OK(err, "bpf_map_lookup_elem"))
		return 0;

	if (!ASSERT_EQ(val.rcv_ssthresh, rcv_ssthresh, "rcv_ssthresh"))
		return 0;

	/* Allow some margin of error for rcv_wnd to account for scaling. */
	if (!ASSERT_GT(val.rcv_wnd, rcv_wnd_min, "rcv_wnd_min"))
		return 0;

	if (!ASSERT_LT(val.rcv_wnd, rcv_wnd_max, "rcv_wnd_max"))
		return 0;

	return -1;
}

static int run_test(int cgroup_fd, int server_fd)
{
	struct bpf_prog_load_attr attr = {
		.prog_type = BPF_PROG_TYPE_SOCK_OPS,
		.file = "./tcp_rcv_ssthresh.o",
		.expected_attach_type = BPF_CGROUP_SOCK_OPS,
	};
	struct bpf_object *obj;
	struct bpf_map *map;
	int client_fd;
	int prog_fd;
	int map_fd;
	int err;

	err = bpf_prog_load_xattr(&attr, &obj, &prog_fd);
	if (err) {
		log_err("Failed to load BPF object");
		return -1;
	}

	map = bpf_object__next_map(obj, NULL);
	map_fd = bpf_map__fd(map);

	err = bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_SOCK_OPS, 0);
	if (err) {
		log_err("Failed to attach BPF program");
		goto close_bpf_object;
	}

	client_fd = connect_to_fd(server_fd, 0);
	if (client_fd < 0) {
		err = -1;
		goto close_bpf_object;
	}

	ASSERT_TRUE(verify_sstresh(map_fd, client_fd, 80000, 80000), "first client ack");

	int server_client_fd = accept(server_fd, NULL, NULL);

	/* The server needs to exchange some data outside of the hanshake
	 * to apply rcv_ssthresh to rcv_wnd and advertise it in an ACK.
	 */
	ASSERT_TRUE(verify_sstresh(map_fd, server_client_fd, 90000, 65535), "syn-ack");

	send_byte(client_fd);
	if (wait_for_ack(client_fd, 100) < 0) {
		err = -1;
		goto close_client_fd;
	}

	ASSERT_TRUE(verify_sstresh(map_fd, client_fd, 80000, 80000), "client sent data");

	send_byte(server_client_fd);
	if (wait_for_ack(server_client_fd, 100) < 0) {
		err = -1;
		goto close_server_client_fd;
	}

	ASSERT_TRUE(verify_sstresh(map_fd, server_client_fd, 90000, 90000), "server sent data");

close_server_client_fd:
	close(server_client_fd);

close_client_fd:
	close(client_fd);

close_bpf_object:
	bpf_object__close(obj);
	return err;
}

void test_tcp_rcv_ssthresh(void)
{
	int server_fd, cgroup_fd;

	cgroup_fd = test__join_cgroup("/tcp_rcv_ssthresh");
	if (!ASSERT_GE(cgroup_fd, 0, "cgroup_fd"))
		return;

	server_fd = start_server(AF_INET, SOCK_STREAM, NULL, 0, 0);
	if (!ASSERT_GE(server_fd, 0, "server_fd"))
		goto close_cgroup_fd;

	run_test(cgroup_fd, server_fd);

	close(server_fd);

close_cgroup_fd:
	close(cgroup_fd);
}
