/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2021 David Woodhouse.
 *
 * Author: David Woodhouse <dwmw2@infradead.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */
#include "../system.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

#include <linux/vhost.h>
#include <sys/eventfd.h>

#include "../conf.h"
#include "../device.h"
#include "../logger.h"
#include "../names.h"
#include "../net.h"
#include "../route.h"
#include "../utils.h"
#include "../xalloc.h"
#include "../device.h"

#include <linux/virtio_net.h>
//#include <linux/vhost.h>

void shutdown_vhost();

struct oc_vring {
	struct vring_desc *desc;
	struct vring_avail *avail;
	struct vring_used *used;
	uint16_t seen_used;
};


#ifdef IF_TUN_HDR
#include IF_TUN_HDR
#endif

#define RING_SIZE 32

struct openconnect_info {
	int vhost_fd, vhost_call_fd, vhost_kick_fd;
	struct oc_vring tx_vring, rx_vring;
   	int need_poll_cmd_fd;
	int cmd_fd_internal;

    // tmp
    int tun_fd;
    int ip_info_mtu;
    int max_qlen;
    const char* quit_reason;
    int pkt_trailer;
};

struct openconnect_info vpninfo;

void monitor_fd_new(int fd){

}

#define vpn_progress(x, ...) printf(__VA_ARGS__);
#define _(x) x

static int setup_vring(int idx)
{
	struct oc_vring *vring = idx ? &vpninfo.tx_vring : &vpninfo.rx_vring;
	int ret;
	if (getenv("NOVHOST"))
		return -EINVAL;
	vring->desc = calloc(RING_SIZE, sizeof(*vring->desc));
	vring->avail = calloc(RING_SIZE + 3, 2);
	vring->used = calloc(1 + (RING_SIZE * 2), 4);

	if (!vring->desc || !vring->avail || !vring->used)
		return -ENOMEM;

	for (int i = 0; i < RING_SIZE; i++)
		vring->avail->ring[i] = i;

	struct vhost_vring_state vs = { };
	vs.index = idx;
	vs.num = RING_SIZE;
	if (ioctl(vpninfo.vhost_fd, VHOST_SET_VRING_NUM, &vs) < 0) {
		ret = -errno;
		vpn_progress(PRG_ERR, _("Failed to set vring #%d size: %s\n"),
			     idx, strerror(-ret));
		return ret;
	}

	vs.num = 0;
	if (ioctl(vpninfo.vhost_fd, VHOST_SET_VRING_BASE, &vs) < 0) {
		ret = -errno;
		vpn_progress(PRG_ERR, _("Failed to set vring #%d base: %s\n"),
			     idx, strerror(-ret));
		return ret;
	}

	struct vhost_vring_addr va = { };
	va.index = idx;
	va.desc_user_addr = (uint64_t)vring->desc;
	va.avail_user_addr = (uint64_t)vring->avail;
	va.used_user_addr  = (uint64_t)vring->used;
	if (ioctl(vpninfo.vhost_fd, VHOST_SET_VRING_ADDR, &va) < 0) {
		ret = -errno;
		vpn_progress(PRG_ERR, _("Failed to set vring #%d base: %s\n"),
			     idx, strerror(-ret));
		return ret;
	}

	struct vhost_vring_file vf = { };
	vf.index = idx;
	vf.fd = vpninfo.tun_fd;
	if (ioctl(vpninfo.vhost_fd, VHOST_NET_SET_BACKEND, &vf) < 0) {
		ret = -errno;
		vpn_progress(PRG_ERR, _("Failed to set vring #%d RX backend: %s\n"),
			     idx, strerror(-ret));
		return ret;
	}

	vf.fd = vpninfo.vhost_call_fd;
	if (ioctl(vpninfo.vhost_fd, VHOST_SET_VRING_CALL, &vf) < 0) {
		ret = -errno;
		vpn_progress(PRG_ERR, _("Failed to set vring #%d call eventfd: %s\n"),
			     idx, strerror(-ret));
		close(vpninfo.vhost_fd);
		return ret;
	}

	vf.fd = vpninfo.vhost_kick_fd;
	if (ioctl(vpninfo.vhost_fd, VHOST_SET_VRING_KICK, &vf) < 0) {
		ret = -errno;
		vpn_progress(PRG_ERR, _("Failed to set vring #%d kick eventfd: %s\n"),
			     idx, strerror(-ret));
		close(vpninfo.vhost_fd);
		return ret;
	}

	return 0;
}
#define OC_VHOST_NET_FEATURES ((1ULL << VHOST_NET_F_VIRTIO_NET_HDR) |	\
			       (1ULL << VIRTIO_F_VERSION_1) |		\
			       (1ULL << VIRTIO_RING_F_EVENT_IDX))

int setup_vhost(int tun_fd)
{
	int ret;

    vpninfo.ip_info_mtu = 1500;
    vpninfo.tun_fd = tun_fd;
    vpninfo.max_qlen = 1000;
    vpninfo.pkt_trailer = 0;

	vpninfo.vhost_fd = open("/dev/vhost-net", O_RDWR);
	if (vpninfo.vhost_fd == -1) {
		ret = -errno;
		vpn_progress(PRG_DEBUG, _("Failed to open /dev/vhost-net: %s\n"),
			     strerror(-ret));
		goto err;
	}

	if (ioctl(vpninfo.vhost_fd, VHOST_SET_OWNER, NULL) < 0) {
		ret = -errno;
		vpn_progress(PRG_DEBUG, _("Failed to set vhost ownership: %s\n"),
			     strerror(-ret));
		goto err;
	}

	uint64_t features;

	if (ioctl(vpninfo.vhost_fd, VHOST_GET_FEATURES, &features) < 0) {
		ret = -errno;
		vpn_progress(PRG_DEBUG, _("Failed to get vhost features: %s\n"),
			     strerror(-ret));
		goto err;
	}
	if ((features & OC_VHOST_NET_FEATURES) != OC_VHOST_NET_FEATURES) {
		vpn_progress(PRG_DEBUG, _("vhost-net lacks required features: %llx\n"),
			     (unsigned long long)features);
		return -EOPNOTSUPP;
	}

	features = OC_VHOST_NET_FEATURES;
	if (ioctl(vpninfo.vhost_fd, VHOST_SET_FEATURES, &features) < 0) {
		ret = -errno;
		vpn_progress(PRG_ERR, _("Failed to set vhost features: %s\n"),
			     strerror(-ret));
		goto err;
	}

	vpninfo.vhost_kick_fd = eventfd(0, EFD_CLOEXEC|EFD_NONBLOCK);
	if (vpninfo.vhost_kick_fd == -1) {
		ret = -errno;
		vpn_progress(PRG_ERR, _("Failed to open vhost kick eventfd: %s\n"),
			     strerror(-ret));
		goto err;
	}
	vpninfo.vhost_call_fd = eventfd(0, EFD_CLOEXEC|EFD_NONBLOCK);
	if (vpninfo.vhost_call_fd == -1) {
		ret = -errno;
		vpn_progress(PRG_ERR, _("Failed to open vhost call eventfd: %s\n"),
			     strerror(-ret));
		goto err;
	}

	struct vhost_memory *vmem = alloca(sizeof(*vmem) + sizeof(vmem->regions[0]));

	memset(vmem, 0, sizeof(*vmem) + sizeof(vmem->regions[0]));
	vmem->nregions = 1;
	vmem->regions[0].guest_phys_addr = 4096;
	vmem->regions[0].memory_size = 0x7fffffffe000; /* Why doesn't it allow 0x7fffffff000? */
	vmem->regions[0].userspace_addr = 4096;
	if (ioctl(vpninfo.vhost_fd, VHOST_SET_MEM_TABLE, vmem) < 0) {
		ret = -errno;
		vpn_progress(PRG_DEBUG, _("Failed to set vhost memory map: %s\n"),
			     strerror(-ret));
		goto err;
	}

	ret = setup_vring(0);
	if (ret)
		goto err;

	ret = setup_vring(1);
	if (ret)
		goto err;

	/* This isn't just for bufferbloat; there are various issues with the XDP
	 * code path:
	 * https://lore.kernel.org/netdev/2433592d2b26deec33336dd3e83acfd273b0cf30.camel@infradead.org/T/
	 */
	int sndbuf = vpninfo.ip_info_mtu;
	if (!sndbuf)
		sndbuf = 1500;
	sndbuf *= 2 * vpninfo.max_qlen;
	if (ioctl(vpninfo.tun_fd, TUNSETSNDBUF, &sndbuf) < 0) {
		ret = -errno;
		vpn_progress(PRG_INFO, _("Failed to set tun sndbuf: %s\n"),
			     strerror(-ret));
		goto err;
	}

	vpn_progress(PRG_INFO, _("Using vhost-net for tun acceleration\n"));

	monitor_fd_new(vpninfo.vhost_call_fd);
	monitor_read_fd(vpninfo.vhost_call_fd);

	return 0;

 err:
	shutdown_vhost();
	return ret;
}

static void free_vring(struct oc_vring *vring)
{
	free(vring->desc);
	vring->desc = NULL;
	free(vring->avail);
	vring->avail = NULL;
	free(vring->used);
	vring->used = NULL;
}

void shutdown_vhost()
{
	if (vpninfo.vhost_fd != -1)
		close(vpninfo.vhost_fd);
	if (vpninfo.vhost_kick_fd != -1)
		close(vpninfo.vhost_kick_fd);
	if (vpninfo.vhost_call_fd != -1)
		close(vpninfo.vhost_call_fd);

	vpninfo.vhost_fd = vpninfo.vhost_kick_fd = vpninfo.vhost_call_fd = -1;

	free_vring(&vpninfo.rx_vring);
	free_vring(&vpninfo.tx_vring);
}

#define pkt_vhdr_offset ((unsigned long)&((struct vpn_packet_t *)NULL)->virtio.h)
#define debug_vhost 0

#define barrier() __sync_synchronize()

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define vio16(x) ((uint16_t)(x))
#define vio32(x) ((uint32_t)(x))
#define vio64(x) ((uint64_t)(x))
#else
#define vio16(x) ((uint16_t)__builtin_bswap16(x))
#define vio32(x) ((uint32_t)__builtin_bswap32(x))
#define vio64(x) ((uint64_t)__builtin_bswap64(x))
#endif

static void dump_vring(struct oc_vring *ring)
{
	vpn_progress(PRG_ERR,
		     "next_avail 0x%x, used idx 0x%x seen_used 0x%x\n",
		     vio16(ring->avail->idx), vio16(ring->used->idx),
		     ring->seen_used);

	vpn_progress(PRG_ERR, "#   ADDR         AVAIL         USED\n");

	for (int i = 0; i < RING_SIZE + 1; i++)
		vpn_progress(PRG_ERR,
			     "%d %p %x %x\n", i,
			     (void *)vio64(ring->desc[i].addr),
			     vio16(ring->avail->ring[i]),
			     vio16(ring->used->ring[i].id));
}

/* With thanks to Eugenio Pérez Martin <eperezma@redhat.com> for writing
 * https://www.redhat.com/en/blog/virtqueues-and-virtio-ring-how-data-travels
 * which saved a lot of time and caffeine in getting this to work. */
static inline int process_ring(int tx, uint64_t *kick)
{
	struct oc_vring *ring = tx ? &vpninfo.tx_vring : &vpninfo.rx_vring;
	const unsigned int ring_mask = RING_SIZE - 1;
	int did_work = 0;

	/* First handle 'used' packets handed back to us from the ring.
	 * For TX packets (incoming from VPN into the tun device) we just
	 * free them now. For RX packets from the tun device we fill in
	 * the length and queue them for sending over the VPN. */
	uint16_t used_idx = vio16(ring->used->idx);
	while (used_idx != ring->seen_used) {
		uint32_t desc = vio32(ring->used->ring[ring->seen_used & ring_mask].id);
		uint32_t len  = vio32(ring->used->ring[ring->seen_used & ring_mask].len);

		if (desc > ring_mask) {
		inval:
			vpn_progress(PRG_ERR,
				     _("Error: vhost gave back invalid descriptor %d, len %d\n"),
				     desc, len);
			dump_vring(ring);
			vpninfo.quit_reason = "vhost error";
			return -EIO;
		}

		uint64_t addr = vio64(ring->desc[desc].addr);
		if (!addr) {
			vpn_progress(PRG_ERR,
				     _("vhost gave back empty descriptor %d\n"),
				     desc);
			dump_vring(ring);
			vpninfo.quit_reason = "vhost error";
			return -EIO;
		}

		struct vpn_packet_t *this = (void *)(addr - pkt_vhdr_offset);

		if (tx) {
			if (debug_vhost)
				printf("Free TX packet %p [%d] [used %d]\n", this, ring->seen_used, used_idx);
			free_pkt(this);
		} else {
			if (len < sizeof(this->virtio.h))
				goto inval;

			this->len = len - sizeof(this->virtio.h);
			if (debug_vhost) {
				printf("RX packet %p(%d) [%d] [used %d]\n", this, this->len, ring->seen_used, used_idx);
				//dump_buf_hex(PRG_INFO, '<', (void *) &this->virtio.h, this->len + sizeof(this->virtio.h));
			}

			queue_packet(&vpninfo.outgoing_queue, this);
			did_work = 1;
		}

		/* Zero the descriptor and line it up in the next slot in the avail ring. */
		ring->desc[desc].addr = 0;
		ring->avail->ring[ring->seen_used++ & ring_mask] = vio32(desc);
	}

	/* Now handle 'avail' and prime the RX ring full of empty buffers, or
	 * the TX ring with anything we have on the VPN incoming queue. */
	uint16_t next_avail = vio16(ring->avail->idx);
	uint32_t desc = ring->avail->ring[next_avail & ring_mask];
	while (!ring->desc[desc].addr) {
		struct vpn_packet_t *this;
		if (tx) {
			this = dequeue_packet(&vpninfo.incoming_queue);
			if (!this)
				break;
			memset(&this->virtio.h, 0, sizeof(this->virtio.h));
		} else {
			int len = vpninfo.ip_info_mtu;
			this = alloc_pkt(len + vpninfo.pkt_trailer);
			if (!this)
				break;
			this->len = len;
		}

		if (!tx)
			ring->desc[desc].flags = vio16(VRING_DESC_F_WRITE);
		ring->desc[desc].addr = vio64((uint64_t)&this->virtio.h);
		ring->desc[desc].len = vio32(this->len + sizeof(this->virtio.h));
		barrier();

		if (debug_vhost) {
			if (tx) {
				printf("Queue TX packet %p at desc %d avail %d\n", this, desc, next_avail);
				//dump_buf_hex(PRG_INFO, '>', (void *)&this->virtio.h, this->len + sizeof(this->virtio.h));
			} else
				printf("Queue RX packet %p at desc %d avail %d\n", this, desc, next_avail);
		}


		ring->avail->idx = vio16(++next_avail);
		barrier();
		uint16_t avail_event = (&ring->used->flags)[2 + (RING_SIZE * 4)];
		barrier();
		if (avail_event == vio16(next_avail-1)) {
			if (debug_vhost)
				printf("kick for %x\n", avail_event);
			*kick = 1;
		} else if (debug_vhost && avail_event) {
			printf("no kick for %x (%x)\n", next_avail, avail_event);
			if (next_avail == avail_event + RING_SIZE)
				dump_vring(ring);
		}

		desc = ring->avail->ring[next_avail & ring_mask];
	}

	return did_work;
}

static int set_ring_wake(struct oc_vring *ring)
{
	uint16_t wake_idx = vio16(ring->seen_used);

	/* Ask it to wake us if the used idx moves on. Note: used_event
	 * is at the end of the *avail* ring, and vice versa. */
	ring->avail->ring[RING_SIZE] = wake_idx;
	barrier();

	/* If it already did, loop again immediately */
	if (ring->used->idx != wake_idx)
		return 1;
	//	printf("wake idx %d\n", wake_idx);
	return 0;
}

int vhost_tun_mainloop(int *timeout, int did_work)
{
	uint64_t kick = 0;

	did_work += process_ring(0, &kick);
	if (vpninfo.quit_reason)
		return 0;

	did_work += process_ring(1, &kick);
	if (vpninfo.quit_reason)
		return 0;

	if (kick) {
		barrier();
		write(vpninfo.vhost_kick_fd, &kick, sizeof(kick));
		did_work = 1;
	}

	/* If we aren't going to have one more turn around the mainloop,
	 * set the wake event indices. And if we find the the rings have
	 * moved on while we're doing that, take one more turn around
	 * the mainloop... */
	return did_work ||
		set_ring_wake(&vpninfo.rx_vring) ||
		set_ring_wake(&vpninfo.tx_vring);
}
