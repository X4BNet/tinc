/*
    device.c -- Interaction BSD tun/tap device
    Copyright (C) 2001-2005 Ivo Timmermans,
                  2001-2009 Guus Sliepen <guus@tinc-vpn.org>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "system.h"

#include "conf.h"
#include "logger.h"
#include "net.h"
#include "route.h"
#include "utils.h"
#include "xalloc.h"

#ifdef HAVE_TUNEMU
#include "bsd/tunemu.h"
#endif

#define DEFAULT_DEVICE "/dev/tun0"

typedef enum device_type {
	DEVICE_TYPE_TUN,
	DEVICE_TYPE_TUNIFHEAD,
	DEVICE_TYPE_TAP,
#ifdef HAVE_TUNEMU
	DEVICE_TYPE_TUNEMU,
#endif
} device_type_t;

int device_fd = -1;
char *device = NULL;
char *iface = NULL;
static char *device_info = NULL;
static int device_total_in = 0;
static int device_total_out = 0;
#if defined(TUNEMU)
static device_type_t device_type = DEVICE_TYPE_TUNEMU;
#elif defined(HAVE_OPENBSD) || defined(HAVE_FREEBSD)
static device_type_t device_type = DEVICE_TYPE_TUNIFHEAD;
#else
static device_type_t device_type = DEVICE_TYPE_TUN;
#endif

bool setup_device(void) {
	char *type;

	cp();

	if(!get_config_string(lookup_config(config_tree, "Device"), &device))
		device = xstrdup(DEFAULT_DEVICE);

	if(!get_config_string(lookup_config(config_tree, "Interface"), &iface))
		iface = xstrdup(rindex(device, '/') ? rindex(device, '/') + 1 : device);

	if(get_config_string(lookup_config(config_tree, "DeviceType"), &type)) {
		if(!strcasecmp(type, "tun"))
			/* use default */;	
#ifdef HAVE_TUNEMU
		else if(!strcasecmp(type, "tunemu"))
			device_type = DEVICE_TYPE_TUNEMU;
#endif
		else if(!strcasecmp(type, "tunnohead"))
			device_type = DEVICE_TYPE_TUN;
		else if(!strcasecmp(type, "tunifhead"))
			device_type = DEVICE_TYPE_TUNIFHEAD;
		else if(!strcasecmp(type, "tap"))
			device_type = DEVICE_TYPE_TAP;
		else {
			logger(LOG_ERR, _("Unknown device type %s!"), type);
			return false;
		}
	} else {
		if(strstr(device, "tap") || routing_mode != RMODE_ROUTER)
			device_type = DEVICE_TYPE_TAP;
	}

	switch(device_type) {
#ifdef HAVE_TUNEMU
		case DEVICE_TYPE_TUNEMU: {
			char dynamic_name[256] = "";
        		device_fd = tunemu_open(dynamic_name);
		}
			break;
#endif
		default:
			device_fd = open(device, O_RDWR | O_NONBLOCK);
	}

	if(device_fd < 0) {
		logger(LOG_ERR, _("Could not open %s: %s"), device, strerror(errno));
		return false;
	}

	switch(device_type) {
		default:
			device_type = DEVICE_TYPE_TUN;
		case DEVICE_TYPE_TUN:
#ifdef TUNSIFHEAD
		{	
			const int zero = 0;
			if(ioctl(device_fd, TUNSIFHEAD, &zero, sizeof zero) == -1) {
				logger(LOG_ERR, _("System call `%s' failed: %s"), "ioctl", strerror(errno));
				return false;
			}
		}
#endif
#if defined(TUNSIFMODE) && defined(IFF_BROADCAST) && defined(IFF_MULTICAST)
		{
			const int mode = IFF_BROADCAST | IFF_MULTICAST;
			ioctl(device_fd, TUNSIFMODE, &mode, sizeof mode);
		}
#endif

			device_info = _("Generic BSD tun device");
			break;
		case DEVICE_TYPE_TUNIFHEAD:
#ifdef TUNSIFHEAD
		{
			const int one = 1;
			if(ioctl(device_fd, TUNSIFHEAD, &one, sizeof one) == -1) {
				logger(LOG_ERR, _("System call `%s' failed: %s"), "ioctl", strerror(errno));
				return false;
			}
		}
#endif
#if defined(TUNSIFMODE) && defined(IFF_BROADCAST) && defined(IFF_MULTICAST)
		{
				const int mode = IFF_BROADCAST | IFF_MULTICAST;
				ioctl(device_fd, TUNSIFMODE, &mode, sizeof mode);
		}
#endif

			device_info = _("Generic BSD tun device");
			break;
		case DEVICE_TYPE_TAP:
			if(routing_mode == RMODE_ROUTER)
				overwrite_mac = true;
			device_info = _("Generic BSD tap device");
			break;
#ifdef HAVE_TUNEMU
		case DEVICE_TYPE_TUNEMU:
        		device_info = _("BSD tunemu device");
			break;
#endif
	}

	logger(LOG_INFO, _("%s is a %s"), device, device_info);

	return true;
}

void close_device(void) {
	cp();

	switch(device_type) {
#ifdef HAVE_TUNEMU
		case DEVICE_TYPE_TUNEMU:
			tunemu_close(device_fd);
			break;
#endif
		default:
			close(device_fd);
	}

	free(device);
	free(iface);
}

bool read_packet(vpn_packet_t *packet) {
	int lenin;

	cp();

	switch(device_type) {
		case DEVICE_TYPE_TUN:
#ifdef HAVE_TUNEMU
		case DEVICE_TYPE_TUNEMU:
			if(device_type == DEVICE_TYPE_TUNEMU)
				lenin = tunemu_read(device_fd, packet->data + 14, MTU - 14);
			else
#else
				lenin = read(device_fd, packet->data + 14, MTU - 14);
#endif

			if(lenin <= 0) {
				logger(LOG_ERR, _("Error while reading from %s %s: %s"), device_info,
					   device, strerror(errno));
				return false;
			}

			switch(packet->data[14] >> 4) {
				case 4:
					packet->data[12] = 0x08;
					packet->data[13] = 0x00;
					break;
				case 6:
					packet->data[12] = 0x86;
					packet->data[13] = 0xDD;
					break;
				default:
					ifdebug(TRAFFIC) logger(LOG_ERR,
							   _ ("Unknown IP version %d while reading packet from %s %s"),
							   packet->data[14] >> 4, device_info, device);
					return false;
			}

			packet->len = lenin + 14;
			break;

		case DEVICE_TYPE_TUNIFHEAD: {
			u_int32_t type;
			struct iovec vector[2] = {{&type, sizeof(type)}, {packet->data + 14, MTU - 14}};

			if((lenin = readv(device_fd, vector, 2)) <= 0) {
				logger(LOG_ERR, _("Error while reading from %s %s: %s"), device_info,
					   device, strerror(errno));
				return false;
			}

			switch (ntohl(type)) {
				case AF_INET:
					packet->data[12] = 0x08;
					packet->data[13] = 0x00;
					break;

				case AF_INET6:
					packet->data[12] = 0x86;
					packet->data[13] = 0xDD;
					break;

				default:
					ifdebug(TRAFFIC) logger(LOG_ERR,
							   _ ("Unknown address family %x while reading packet from %s %s"),
							   ntohl(type), device_info, device);
					return false;
			}

			packet->len = lenin + 10;
			break;
		}

		case DEVICE_TYPE_TAP:
			if((lenin = read(device_fd, packet->data, MTU)) <= 0) {
				logger(LOG_ERR, _("Error while reading from %s %s: %s"), device_info,
					   device, strerror(errno));
				return false;
			}

			packet->len = lenin;
			break;

		default:
			return false;
	}
		
	device_total_in += packet->len;

	ifdebug(TRAFFIC) logger(LOG_DEBUG, _("Read packet of %d bytes from %s"),
			   packet->len, device_info);

	logger(LOG_INFO, "E:fd_read");
	return true;
}

bool write_packet(vpn_packet_t *packet)
{
	cp();

	ifdebug(TRAFFIC) logger(LOG_DEBUG, _("Writing packet of %d bytes to %s"),
			   packet->len, device_info);

	switch(device_type) {
		case DEVICE_TYPE_TUN:
			if(write(device_fd, packet->data + 14, packet->len - 14) < 0) {
				logger(LOG_ERR, _("Error while writing to %s %s: %s"), device_info,
					   device, strerror(errno));
				return false;
			}
			break;

		case DEVICE_TYPE_TUNIFHEAD: {
			u_int32_t type;
			struct iovec vector[2] = {{&type, sizeof(type)}, {packet->data + 14, packet->len - 14}};
			int af;
			
			af = (packet->data[12] << 8) + packet->data[13];

			switch (af) {
				case 0x0800:
					type = htonl(AF_INET);
					break;
				case 0x86DD:
					type = htonl(AF_INET6);
					break;
				default:
					ifdebug(TRAFFIC) logger(LOG_ERR,
							   _("Unknown address family %x while writing packet to %s %s"),
							   af, device_info, device);
					return false;
			}

			if(writev(device_fd, vector, 2) < 0) {
				logger(LOG_ERR, _("Can't write to %s %s: %s"), device_info, device,
					   strerror(errno));
				return false;
			}
			break;
		}
			
		case DEVICE_TYPE_TAP:
			if(write(device_fd, packet->data, packet->len) < 0) {
				logger(LOG_ERR, _("Error while writing to %s %s: %s"), device_info,
					   device, strerror(errno));
				return false;
			}
			break;

#ifdef HAVE_TUNEMU
		case DEVICE_TYPE_TUNEMU:
			if(tunemu_write(device_fd, packet->data + 14, packet->len - 14) < 0) {
				logger(LOG_ERR, _("Error while writing to %s %s: %s"), device_info,
					   device, strerror(errno));
				return false;
			}
			break;
#endif

		default:
			return false;
	}

	device_total_out += packet->len;

	return true;
}

void dump_device_stats(void)
{
	cp();

	logger(LOG_DEBUG, _("Statistics for %s %s:"), device_info, device);
	logger(LOG_DEBUG, _(" total bytes in:  %10d"), device_total_in);
	logger(LOG_DEBUG, _(" total bytes out: %10d"), device_total_out);
}
