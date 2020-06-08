/** @file ptp_packet.c
* PTP packet interface for Linux.
*/

/*
    Openptp is an open source PTP version 2 (IEEE 1588-2008) daemon.
    
    Copyright (C) 2007-2009  Flexibilis Oy

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 
    as published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

/******************************************************************************
* $Id$
******************************************************************************/
#include <fcntl.h>
#include <sys/types.h>

#include <packet_if.h>
#include <os_if.h>
#include <ptp_general.h>
#include <ptp_message.h>
#include <ptp_config.h>
#include <ptp_internal.h>
#include <ptp.h>

#include <WinSock2.h>
#include <Ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

#include <Iphlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib")

#include <Mswsock.h>

#define IFHWADDRLEN MAX_ADAPTER_ADDRESS_LENGTH
#define IFNAMSIZ MAX_ADAPTER_NAME_LENGTH

/**
 * Interface data.
 */
struct linux_if_interface {
    char if_name[IFNAMSIZ];
    int if_index;
    struct in_addr if_addr;     ///< local IP address
    int unicast_entry;          ///< set to 1 if unicast destination
    struct in_addr net_addr;    ///< destination IP addr
    u8 hw_addr[IFHWADDRLEN];
    struct interface_config *if_config; ///< pointer to associated if config
};

/**
 * Holds socket etc. data.
 */
struct linux_packet_if {
    SOCKET event_sock;
    SOCKET gen_sock;
    int num_interfaces;
    struct linux_if_interface interfaces[MAX_NUM_INTERFACES];
};
static struct linux_packet_if packet_if_data;

// function for searching interfaces to use
static int locate_interfaces(struct linux_packet_if *pif);
// function for receiving PTP message from socket
static int ptp_receive_msg(struct linux_packet_if *pif, SOCKET sock,
                           int *if_index, char *frame, int *length,
                           struct Timestamp *recv_time,
                           struct sockaddr_in *from_addr);
// interface location
static struct linux_if_interface *get_interface(struct linux_packet_if
                                                *pif, int *if_index,
                                                char *if_name,
                                                int *port_num);
// Helpers for port id vs. hw address
static void create_clock_id(ClockIdentity clk_id, u8 * hwaddr);
// if_num port_num conversions
static int if_num_to_port_num(int if_num);
//static int port_num_to_if_num( int port_num );

static int if_configured(char *if_name);

static LPFN_WSARECVMSG WSARecvMsg;
//static LPFN_WSASENDMSG WSASendMsg;

// Local macros
#define MIN(a,b) ((a)<(b)?(a):(b))

#ifndef WIN32
#ifndef SO_TIMESTAMPNS
#warning "nanosecond support disabled"
#endif
#endif

/**
* Function for initializing packet interface. 
* @param ctx packet if context
* @param cfg_file Config file name for packet interface.
* @return ptp error code.
*/
int ptp_initialize_packet_if(struct packet_ctx *ctx, char* cfg_file)
{
    struct linux_packet_if *pif = &packet_if_data;
    struct sockaddr_in saddr;
	IP_MREQ ip_mreq;
    int tmp = 0, ret = 0;
    ClockIdentity identity;
    int if_num = 0;

    memset(&packet_if_data, 0, sizeof(struct linux_packet_if));

    // Store internal data
    ctx->arg = pif;

	WORD wVersionRequested = MAKEWORD(2, 2);
	WSADATA wsaData;
	WSAStartup(wVersionRequested, &wsaData);

    // Open sockets
    pif->event_sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (pif->event_sock == 0) {
        perror("socket");
        LOG_ERROR("\n");
        return PTP_ERR_NET;
    }

    pif->gen_sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (pif->gen_sock == 0) {
        perror("socket");
        LOG_ERROR("\n");
        return PTP_ERR_NET;
    }
#if 0
    tmp = 1;                    // allow address reuse
    if (setsockopt(pif->event_sock, SOL_SOCKET, SO_REUSEADDR,
                   &tmp, sizeof(int)) != 0) {
        perror("setsockopt");
        LOG_ERROR("\n");
        return PTP_ERR_NET;
    }
    if (setsockopt(pif->gen_sock, SOL_SOCKET, SO_REUSEADDR,
                   &tmp, sizeof(int)) != 0) {
        perror("setsockopt");
        LOG_ERROR("\n");
        return PTP_ERR_NET;
    }
#endif
    // Get list of interfaces
    ret = locate_interfaces(pif);
    if (ret != PTP_ERR_OK) {
        LOG_ERROR("No interfaces found\n");
        return ret;
    }
    if (pif->num_interfaces == 0) {
        LOG_ERROR("No interfaces found\n");
        return PTP_ERR_NET;
    }
    // Create clock id (HW address of the first applicable interface)
    create_clock_id(identity, pif->interfaces[0].hw_addr);

    // Bind sockets
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);  // needed to get multicast in
    saddr.sin_port = htons(DEFAULT_EVENT_PORT);
    DEBUG("Bind %s:%i\n",
          inet_ntoa(saddr.sin_addr), ntohs(saddr.sin_port));
    if (bind(pif->event_sock, (struct sockaddr *) &saddr,
             sizeof(struct sockaddr_in)) != 0) {
        perror("bind");
        LOG_ERROR("\n");
        return PTP_ERR_NET;
    }
    saddr.sin_port = htons(DEFAULT_GENERAL_PORT);
    DEBUG("Bind %s:%i\n",
          inet_ntoa(saddr.sin_addr), ntohs(saddr.sin_port));
    if (bind(pif->gen_sock, (struct sockaddr *) &saddr,
             sizeof(struct sockaddr_in)) != 0) {
        perror("bind");
        LOG_ERROR("\n");
        return PTP_ERR_NET;
    }
    // initialize all usable interfaces
    for (if_num = 0; if_num < pif->num_interfaces; if_num++) {
        DEBUG("DST %s\n", inet_ntoa(pif->interfaces[if_num].net_addr));

        if (pif->interfaces[if_num].unicast_entry == 0) {
            // Set socket options
            // Set multicast options
            // add multicast if
            ip_mreq.imr_multiaddr.s_addr =
                pif->interfaces[if_num].net_addr.s_addr;
            ip_mreq.imr_interface.s_addr =
                pif->interfaces[if_num].if_addr.s_addr;
			DWORD interfaceIndex = htonl(pif->interfaces[if_num].if_index);
            DEBUG("Local %s:%i\n",
                  inet_ntoa(pif->interfaces[if_num].if_addr),
                  pif->interfaces[if_num].if_index);
            DEBUG("Group %s\n",
                  inet_ntoa(pif->interfaces[if_num].net_addr));
            if (setsockopt(pif->event_sock, IPPROTO_IP, IP_MULTICAST_IF, &interfaceIndex,
                           sizeof(interfaceIndex)) != 0) {
                perror("setsockopt");
                LOG_ERROR("\n");
                return PTP_ERR_NET;
            }
            if (setsockopt(pif->gen_sock, IPPROTO_IP, IP_MULTICAST_IF,
                           &interfaceIndex, sizeof(interfaceIndex)) != 0) {
                perror("setsockopt");
                LOG_ERROR("\n");
                return PTP_ERR_NET;
            }
            if (setsockopt(pif->event_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                           &ip_mreq, sizeof(IP_MREQ)) != 0) {
                perror("setsockopt");
                LOG_ERROR("\n");
                return PTP_ERR_NET;
            }
            if (setsockopt(pif->gen_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                           &ip_mreq, sizeof(IP_MREQ)) != 0) {
                perror("setsockopt");
                LOG_ERROR("\n");
                return PTP_ERR_NET;
            }
        }
    }

    tmp = 1;                    // set multicast TTL to 1
    if (setsockopt(pif->event_sock, IPPROTO_IP, IP_MULTICAST_TTL,
                   &tmp, sizeof(int)) != 0) {
        perror("setsockopt");
        LOG_ERROR("\n");
        return PTP_ERR_NET;
    }
    if (setsockopt(pif->gen_sock, IPPROTO_IP, IP_MULTICAST_TTL,
                   &tmp, sizeof(int)) != 0) {
        perror("setsockopt");
        LOG_ERROR("\n");
        return PTP_ERR_NET;
    }

    tmp = 1;                // enable multicast loopback 
    if (setsockopt(pif->event_sock, IPPROTO_IP, IP_MULTICAST_LOOP,
                   &tmp, sizeof(int)) != 0) {
        perror("setsockopt");
        LOG_ERROR("\n");
        return PTP_ERR_NET;
    }
    if (setsockopt(pif->gen_sock, IPPROTO_IP, IP_MULTICAST_LOOP,
                   &tmp, sizeof(int)) != 0) {
        perror("setsockopt");
        LOG_ERROR("\n");
        return PTP_ERR_NET;
    }

    tmp = 1;                    // enable receiving of timestamps on both ports

    /* disable UDP checksum calculation in event port */

    tmp = 1;                    // enable receiving of packet info on event port
	if (setsockopt(pif->event_sock, IPPROTO_IP, IP_PKTINFO,
                   &tmp, sizeof(int)) != 0) {
        perror("setsockopt");
        LOG_ERROR("\n");
        return PTP_ERR_NET;
    }
    tmp = 1;                    // enable receiving of packet info on general port
	if (setsockopt(pif->gen_sock, IPPROTO_IP, IP_PKTINFO, &tmp, sizeof(int)) !=
        0) {
        perror("setsockopt");
        LOG_ERROR("\n");
        return PTP_ERR_NET;
    }
    // Set sockets non-blocking
	//TODO

    for (if_num = 0; if_num < pif->num_interfaces; if_num++) {
        ptp_new_port(if_num_to_port_num(if_num), 
                     identity,
                     pif->interfaces[if_num].unicast_entry,
                     pif->interfaces[if_num].if_config);
    }
    DEBUG("pif: %p\n", pif);

	GUID WSARecvMsg_GUID = WSAID_WSARECVMSG;
	GUID WSASendMsg_GUID = WSAID_WSASENDMSG;
	DWORD numberOfBytes;
	WSAIoctl(pif->gen_sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
		&WSARecvMsg_GUID, sizeof WSARecvMsg_GUID,
		&WSARecvMsg, sizeof WSARecvMsg,
		&numberOfBytes, NULL, NULL);

	//WSAIoctl(pif->gen_sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
	//	&WSASendMsg_GUID, sizeof WSASendMsg_GUID,
	//	&WSASendMsg, sizeof WSASendMsg,
	//	&numberOfBytes, NULL, NULL);

    return PTP_ERR_OK;
}

/**
* Function for reconfiguring packet interface. 
* @param ctx packet if context
* @param cfg_file Config file name for packet interface.
* @return ptp error code.
*/
int ptp_reconfig_packet_if(struct packet_ctx *ctx, char* cfg_file)
{
//    struct linux_packet_if *pif = (struct linux_packet_if*)ctx->arg;

    return PTP_ERR_OK;
}

/**
* Function for closing packet interface. 
* @param ctx packet if context
* @return ptp error code.
*/
int ptp_close_packet_if(struct packet_ctx *ctx)
{
    struct linux_packet_if *pif = (struct linux_packet_if *) ctx->arg;
    IP_MREQ ip_mreq;
    int if_num = 0;


    for (if_num = 0; if_num < pif->num_interfaces; if_num++) {
        ptp_close_port(pif->interfaces[if_num].if_index);
        // drop multicast if
		ip_mreq.imr_multiaddr.s_addr = pif->interfaces[if_num].net_addr.s_addr;
		ip_mreq.imr_interface.s_addr = pif->interfaces[if_num].if_addr.s_addr;
		if (setsockopt(pif->event_sock, IPPROTO_IP, IP_DROP_MEMBERSHIP,
                       &ip_mreq, sizeof(IP_MREQ)) != 0) {
            perror("setsockopt");
            LOG_ERROR("\n");
            return PTP_ERR_NET;
        }
    }
    pif->num_interfaces = 0;
    closesocket(pif->event_sock);
	closesocket(pif->gen_sock);

	WSACleanup();

    ctx->arg = 0;

    return PTP_ERR_OK;
}

/**
* Function for sending PTP frames. 
* @see frame_sent.
* @param ctx packet if context
* @param msg_type ptp message type
* @param port_num port number.
* @param frame frame to send.
* @param length frame length.
* @return ptp error code.
*/
int ptp_send(struct packet_ctx *ctx,
             int msg_type, int port_num, char *frame, int length)
{
    struct linux_packet_if *pif = (struct linux_packet_if *) ctx->arg;
	SOCKADDR_IN saddr;
    int if_num = port_num - 1;
    WSAMSG info_msg;
    WSABUF vec[1];
    union {
		WSACMSGHDR cmsg;
		char buf[WSA_CMSG_SPACE(sizeof(IN_PKTINFO))];
    } cmsg_data;
	WSACMSGHDR *cmsg_tmp = 0;
    struct in_pktinfo *pkt_info = 0;
	DWORD numberOfBytesSent = 0;

	memset(&info_msg, 0, sizeof(WSACMSGHDR));
    memset(&cmsg_data, 0, sizeof(cmsg_data));

    cmsg_tmp = &cmsg_data.cmsg;
	cmsg_tmp->cmsg_level = IPPROTO_IP;
    cmsg_tmp->cmsg_type = IP_PKTINFO;
	cmsg_tmp->cmsg_len = WSA_CMSG_SPACE(sizeof(IN_PKTINFO));

    // Create needed structures
    vec[0].buf = frame;
    vec[0].len = length;

    info_msg.name = &saddr;
    info_msg.namelen = sizeof(struct sockaddr_in);
    info_msg.lpBuffers = vec;
    info_msg.dwBufferCount = 1;
    info_msg.Control.buf = cmsg_data.buf;
    info_msg.Control.len = sizeof(cmsg_data.buf);
    info_msg.dwFlags = 0;

	pkt_info = (IN_PKTINFO *)WSA_CMSG_DATA(cmsg_tmp);
    pkt_info->ipi_ifindex = pif->interfaces[if_num].if_index;
    if ((if_num >= pif->num_interfaces) || (if_num < 0)) {
        LOG_ERROR("port number");
        return PTP_ERR_GEN;
    }

    switch (msg_type) {
        // Event messages
    case PTP_SYNC:
    case PTP_DELAY_REQ:
    case PTP_PDELAY_REQ:
    case PTP_PDELAY_RESP:
        saddr.sin_family = AF_INET;
        saddr.sin_port = htons(DEFAULT_EVENT_PORT);
        saddr.sin_addr.s_addr = pif->interfaces[if_num].net_addr.s_addr;
        DEBUG("Send event to %s:%i %i %i:%s\n",
              inet_ntoa(pif->interfaces[if_num].net_addr),
              ntohs(saddr.sin_port),
              length, port_num, inet_ntoa(saddr.sin_addr));
		if (WSASendMsg(pif->event_sock, &info_msg, 0, &numberOfBytesSent, NULL, NULL) != 0) {
            perror("WSASendMsg");
			LOG_ERROR("Failed calling WSASendMsg (event): error %i\n", WSAGetLastError());
		}
        break;
        // General messages
    case PTP_FOLLOW_UP:
    case PTP_DELAY_RESP:
    case PTP_PDELAY_RESP_FOLLOW_UP:
    case PTP_ANNOUNCE:
    case PTP_SIGNALING:
    case PTP_MANAGEMENT:
        saddr.sin_family = AF_INET;
        saddr.sin_port = htons(DEFAULT_GENERAL_PORT);
        saddr.sin_addr.s_addr = pif->interfaces[if_num].net_addr.s_addr;
        DEBUG("Send general to %s:%i %i\n",
              inet_ntoa(pif->interfaces[if_num].net_addr),
              ntohs(saddr.sin_port), length);
		if (WSASendMsg(pif->event_sock, &info_msg, 0, &numberOfBytesSent, NULL, NULL) != 0) {
            perror("WSASendMsg");
			LOG_ERROR("Failed calling WSASendMsg: error %i\n", WSAGetLastError());
        }
        break;
    }
    return PTP_ERR_OK;
}

/**
* Function for receiving PTP frames. Function can be used to poll PTP ports
* and if no frames are available, error code PTP_ERROR_TIMEOUT is returned.
* @param ctx packet if context
* @param timeout_usec receive timeout in microsecs, decremented with used time.
* @param port_num port number.
* @param frame buffer for received frame.
* @param length frame buffer length.
* @param recv_time timestamp for received frame.
* @param peer_addr Peer address returned here if not NULL.
* @return ptp error code.
*/
int ptp_receive(struct packet_ctx *ctx,
                u32 * timeout_usec,
                int *port_num,
                char *frame, 
                int *length, 
                struct Timestamp *recv_time,
                char *peer_addr)
{
    struct linux_packet_if *pif = (struct linux_packet_if *) ctx->arg;
    int ret = PTP_ERR_OK;
    struct timeval tval_select;
    fd_set rd_fd;
    int recv_buffer_len = *length;
    int if_index = 0;
    struct sockaddr_in from_addr;

    FD_ZERO(&rd_fd);
    FD_SET(pif->event_sock, &rd_fd);
    FD_SET(pif->gen_sock, &rd_fd);

    if (*timeout_usec == 0) {
        // Zero timeout, this may cause problems! Force timeout!            
        LOG_ERROR("Force timeout\n");
        *timeout_usec = 10;
    }

  restart_recv:                // Done only if non-valid or own frame is recvd

    tval_select.tv_sec = 0;
    tval_select.tv_usec = *timeout_usec;
    DEBUG("timeout %uus\n", *timeout_usec);

    ret = select(ptp_max(pif->event_sock, pif->gen_sock) + 1,
                 &rd_fd, 0, 0, &tval_select);
    if (ret < 0) {
        perror("select\n");
        ret = PTP_ERR_NET;
    } else if (ret == 0) {
        ret = PTP_ERR_TIMEOUT;
        *timeout_usec = 0;
    } else {
        // Data available
        DEBUG("recv %i\n", ret);

        // update timeout with elapsed time
        *timeout_usec = tval_select.tv_usec;

        *length = recv_buffer_len;
        ret = ptp_receive_msg(pif, pif->event_sock, &if_index,
                              frame, length, recv_time, &from_addr);
        
        if (ret != PTP_ERR_OK) {
            *length = recv_buffer_len;
            ret = ptp_receive_msg(pif, pif->gen_sock, &if_index,
                                  frame, length, recv_time, &from_addr);
        }
        if (ret == PTP_ERR_OK) {
            // Message received successfully, do sanity check for the frame.
            struct ptp_header *hdr = (struct ptp_header *) frame;

            // get port_num
            get_interface(pif, &if_index, NULL, port_num);

            // Check lengths (sanity)
            if (*length < sizeof(struct ptp_header)) {
                LOG_ERROR("Truncated PTP message\n");
                ret = PTP_ERR_GEN;
            }
            switch (hdr->msg_type & 0x0f) {
            case PTP_SYNC:
                if (*length < sizeof(struct ptp_sync)) {
                    LOG_ERROR("Truncated SYNC message %i<%i\n",
                          *length, sizeof(struct ptp_sync));
                    goto restart_recv;
                }
                break;
            case PTP_FOLLOW_UP:
                if (*length < sizeof(struct ptp_follow_up)) {
                    LOG_ERROR("Truncated FOLLOW_UP message %i<%i\n",
                          *length, sizeof(struct ptp_follow_up));
                    goto restart_recv;
                }
                break;
            case PTP_DELAY_REQ:
                if (*length < sizeof(struct ptp_delay_req)) {
                    LOG_ERROR("Truncated DELAY_REQ message %i<%i\n",
                          *length, sizeof(struct ptp_delay_req));
                    goto restart_recv;
                }
                break;
            case PTP_ANNOUNCE:
                if (*length < sizeof(struct ptp_announce)) {
                    LOG_ERROR("Truncated ANNOUNCE message %i<%i\n",
                          *length, sizeof(struct ptp_announce));
                    goto restart_recv;
                }
                break;
            case PTP_DELAY_RESP:
                if (*length < sizeof(struct ptp_delay_resp)) {
                    LOG_ERROR("Truncated Delay_Resp message %i<%i\n",
                          *length, sizeof(struct ptp_delay_resp));
                    goto restart_recv;
                }
                break;
            case PTP_PDELAY_REQ:
            case PTP_PDELAY_RESP:
            case PTP_PDELAY_RESP_FOLLOW_UP:
            case PTP_SIGNALING:
            case PTP_MANAGEMENT:
                break;
            }
            if (compare_clock_id(hdr->src_port_id.clock_identity,
                                 ptp_ctx.default_dataset.clock_identity) ==
                0) {
                // This frame was sent by us. 
                // Check port_number
                if (ntohs(hdr->src_port_id.port_number) != *port_num) {
                    // Loopback from different interface, discard
                    DEBUG("port_num mismatch\n");
                    goto restart_recv;  // frame consumed, restart recv process.
                }
                DEBUG("OWN frame\n");

                ptp_frame_sent(*port_num, hdr, PTP_ERR_OK, recv_time);
                goto restart_recv;      // frame consumed, restart recv process.
            }
            // Store peer IP
            if( peer_addr ){
                inet_pton(AF_INET, peer_addr, &from_addr.sin_addr);
            } 
        }
    }

    return ret;
}

 /**
* Function for receiving PTP messages from a specific socket. 
* @param pif linux packet if context
* @param sock socket. 
* @param if_index interface index.
* @param frame buffer for received frame.
* @param length frame buffer length.
* @param recv_time timestamp for received frame.
* @param from_addr Place for peer IP address.
* @return ptp error code.
*/
static int ptp_receive_msg(struct linux_packet_if *pif,
                           SOCKET sock,
                           int *if_index,
                           char *frame,
                           int *length, 
                           struct Timestamp *recv_time,
                           struct sockaddr_in *from_addr )
{
	WSAMSG info_msg;
	DWORD info_msg_bytes_recvd;
    union {
        struct cmsghdr cmsg;
		char buf[WSA_CMSG_SPACE(sizeof(struct in_pktinfo)) +
                 WSA_CMSG_SPACE(sizeof(struct timeval))];
    } cmsg_data;
    struct cmsghdr *cmsg_tmp = 0;
    struct in_pktinfo *pkt_info = 0;
#ifdef SO_TIMESTAMPNS
    struct timespec *tspec = 0;
#endif
    struct Timestamp *tval = 0;
    int ret = 0;

    // Create needed structures

    memset(from_addr, 0, sizeof(struct sockaddr_in));
    memset(&cmsg_data, 0, sizeof(cmsg_data));

	ret = WSARecvMsg(sock, &info_msg, &info_msg_bytes_recvd, NULL, NULL);
    if (ret < 0) {
        return PTP_ERR_NET;
    }
    // handle msgs
    if (info_msg.Control.len < sizeof(struct cmsghdr) ||
        info_msg.dwFlags & MSG_CTRUNC) {
        DEBUG("No timestamp nor pktinfo\n");
		ptp_get_time(NULL, recv_time);
    }
    for (cmsg_tmp = CMSG_FIRSTHDR(&info_msg);
         cmsg_tmp != NULL; cmsg_tmp = CMSG_NXTHDR(&info_msg, cmsg_tmp)) {
        if (cmsg_tmp->cmsg_level == SOL_SOCKET) {
			ptp_get_time(NULL, recv_time);
            DEBUG("TIMESTAMP %us %uns\n", (u32) recv_time->seconds,
                  (u32) recv_time->nanoseconds);
        }
		else if (cmsg_tmp->cmsg_level == IPPROTO_IP
                 && cmsg_tmp->cmsg_type == IP_PKTINFO) {
			pkt_info = (struct in_pktinfo *) WSA_CMSG_DATA(cmsg_tmp);
            *if_index = pkt_info->ipi_ifindex;
#ifndef WIN32
            DEBUG("IP(%i): %s %s\n", *if_index,
                  inet_ntoa(pkt_info->ipi_spec_dst),
                  inet_ntoa(pkt_info->ipi_addr));
#else
            DEBUG("IP(%i): %s\n", *if_index,
                  inet_ntoa(pkt_info->ipi_addr));
#endif
        } else {
            LOG_ERROR("Unknown msg\n");
        }
    }

    DEBUG("recvmsg(%i) %i %us %uns\n",
          sock, ret, (unsigned int) recv_time->seconds,
          (unsigned int) recv_time->nanoseconds);
    *length = ret;
    return PTP_ERR_OK;
}


#define WORKING_BUFFER_SIZE 15000

// Helper functions
/**
* Function for locating packet interface. 
* @param pif linux packet if context
* @return ptp error code.
*/
static int locate_interfaces(struct linux_packet_if *pif)
{
	PIP_ADAPTER_ADDRESSES pAddresses = NULL;
	PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
	INTERFACE_INFO dev[MAX_NUM_INTERFACES];
	DWORD devBytesReturned;
    int num_if = 0;
    int flags = 0, i = 0, index_if = 0, num_interfaces = 0, cfg_if_index =
        0;
    int ret = PTP_ERR_NET;
    int tmp_index = 0, prev_index = -1;
	ULONG outBufLen = 15*1024;
	DWORD dwRetVal = 0;

    flags = IFF_UP | /*IFF_RUNNING |*/ IFF_MULTICAST;

    // Get list of interfaces
	if (WSAIoctl(pif->event_sock, SIO_GET_INTERFACE_LIST, NULL, 0, &dev, sizeof(dev), &devBytesReturned, 0, 0) == SOCKET_ERROR) {
        perror("Failed calling WSAIoctrl");
		LOG_ERROR("Failed calling WSAIoctrl: error %i\n", WSAGetLastError());
        return PTP_ERR_NET;
    }

	num_if = devBytesReturned / sizeof(INTERFACE_INFO);
    DEBUG("num_if %i\n", num_if);

	i = 0;
	do
	{
		pAddresses = (IP_ADAPTER_ADDRESSES *)malloc(outBufLen);
		dwRetVal = GetAdaptersAddresses(AF_INET, 0, NULL, pAddresses, &outBufLen);

		if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
			free(pAddresses);
			pAddresses = NULL;
		}
		else {
			break;
		}

		i++;
	} while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (i < 3));

	if (dwRetVal == NO_ERROR)
	{
		pCurrAddresses = pAddresses;
		while (pCurrAddresses) {

			/* Check if this interface is accepted: flags ok and 
			 * not same interface as previous (=logical) */
			if (pCurrAddresses->OperStatus == IfOperStatusUp
				&& (pCurrAddresses->Ipv4Enabled)
				&& (!pCurrAddresses->NoMulticast)) {

				char if_name[IFNAMSIZ];
				wcstombs(if_name, pCurrAddresses->FriendlyName, sizeof(if_name));
				cfg_if_index = if_configured(if_name);

				if ((cfg_if_index != -1) && (prev_index != tmp_index)) {
					// This one is ok for us
					prev_index = tmp_index;

					struct in_addr if_addr;
					for (PIP_ADAPTER_UNICAST_ADDRESS pUnicastAddress = pCurrAddresses->FirstUnicastAddress; pUnicastAddress != NULL; pUnicastAddress = pUnicastAddress->Next)
					{
						if (pUnicastAddress->Address.lpSockaddr->sa_family == AF_INET) {
							if_addr = ((PSOCKADDR_IN)pUnicastAddress->Address.lpSockaddr)->sin_addr;
						}
					}

					if (ptp_cfg.interfaces[cfg_if_index].multicast_ena) {
						// Copy name
						memcpy(pif->interfaces[pif->num_interfaces].if_name, if_name, IFNAMSIZ);
						// Copy ifindex
						pif->interfaces[pif->num_interfaces].if_index = pCurrAddresses->IfIndex;
						memcpy(pif->interfaces[pif->num_interfaces].hw_addr, pCurrAddresses->PhysicalAddress, IFHWADDRLEN);
						pif->interfaces[pif->num_interfaces].if_addr = if_addr;
						pif->interfaces[pif->num_interfaces].unicast_entry = 0;
						// copy dst addresses 
						if (inet_pton(AF_INET, PTP_PRIMARY_MULTICAST_IP,
							&pif->interfaces[pif->num_interfaces].
							net_addr) == 0) {
							perror("inet_pton");
							LOG_ERROR("\n");
							return PTP_ERR_NET;
						}
						pif->interfaces[pif->num_interfaces].if_config =
							&ptp_cfg.interfaces[cfg_if_index];

						ret = PTP_ERR_OK;
						pif->num_interfaces++;
						if (pif->num_interfaces >= MAX_NUM_INTERFACES) {
							goto error_out;
						}
					}
					num_interfaces =
						ptp_cfg.interfaces[cfg_if_index].num_unicast_addr;
					for (index_if = 0; index_if < num_interfaces; index_if++) {
						// Copy name
						memcpy(pif->interfaces[pif->num_interfaces].if_name,
							   if_name, IFNAMSIZ);
						// Copy ifindex
						pif->interfaces[pif->num_interfaces].if_index = tmp_index;
						pif->interfaces[pif->num_interfaces].unicast_entry = 1;
						// copy dst addresses 
						if (inet_pton(AF_INET, ptp_cfg.interfaces[cfg_if_index].unicast_ip[index_if],
							 &pif->interfaces[pif->num_interfaces].net_addr) == 0) {
							perror("inet_aton");
							LOG_ERROR("\n");
							return PTP_ERR_NET;
						}
						memcpy(pif->interfaces[pif->num_interfaces].hw_addr,
							pCurrAddresses->PhysicalAddress, IFHWADDRLEN);
						pif->interfaces[pif->num_interfaces].if_addr = if_addr;

						pif->interfaces[pif->num_interfaces].if_config = 
							&ptp_cfg.interfaces[cfg_if_index];

						ret = PTP_ERR_OK;
						pif->num_interfaces++;
						if (pif->num_interfaces >= MAX_NUM_INTERFACES) {
							goto error_out;
						}
					}
				}
			}

			pCurrAddresses = pCurrAddresses->Next;
		}
	}
	else {
		LOG_ERROR("Call to GetAdaptersAddresses failed with error: %d\n", dwRetVal);
	}

	if (pAddresses) {
		free(pAddresses);
	}

    for (i = 0; i < pif->num_interfaces; i++) {
        DEBUG("%i %s %i %s %02x:%02x:%02x:%02x:%02x:%02x\n", i,
              pif->interfaces[i].if_name,
              pif->interfaces[i].if_index,
              inet_ntoa(pif->interfaces[i].if_addr),
              pif->interfaces[i].hw_addr[0],
              pif->interfaces[i].hw_addr[1],
              pif->interfaces[i].hw_addr[2],
              pif->interfaces[i].hw_addr[3],
              pif->interfaces[i].hw_addr[4],
              pif->interfaces[i].hw_addr[5]);
    }

    return ret;

  error_out:
	if (pAddresses) {
		free(pAddresses);
	}
    LOG_ERROR("Maximum number of interfaces exceeded\n");
    return PTP_ERR_NET;
}

/**
* Create port id from hwaddr. 
* @param clk_id clock id (destination)
* @param hwaddr HW address (source)
*/
static void create_clock_id(ClockIdentity clk_id, u8 * hwaddr)
{
    // Create clock id
    clk_id[0] = hwaddr[0];
    clk_id[1] = hwaddr[1];
    clk_id[2] = hwaddr[2];
    clk_id[3] = 0xff;
    clk_id[4] = 0xfe;
    clk_id[5] = hwaddr[3];
    clk_id[6] = hwaddr[4];
    clk_id[7] = hwaddr[5];
}

/**
* Convert if_num (index in linux_packet_if.interfaces) to port number. 
* @param if_number (linux_packet_if.interfaces index)
* @return port_num.
*/
static int if_num_to_port_num(int if_num)
{
    return if_num + 1;
}

/**
* Convert port number to if_num (index in linux_packet_if.interfaces).
* @param port_num port number. 
* @return if_num (linux_packet_if.interfaces index)
*/
/*
static int port_num_to_if_num( int port_num ){
    return port_num-1;
}
*/

/**
* Locate correct interface. 
* @param pif Linux packet if ctx
* @param if_index interface index (NULL if not used)
* @param if_name interface name (NULL if not used)
* @param port_num return port number (NULL if not used)
* @return pointer to interface ctx, NULL if not found
*/
static struct linux_if_interface *get_interface(struct linux_packet_if
                                                *pif, int *if_index,
                                                char *if_name,
                                                int *port_num)
{
    int i = 0;
    if (if_index && if_name) {  // both given
        for (i = 0; i < pif->num_interfaces; i++) {
            if ((*if_index == pif->interfaces[i].if_index) &&
                (strncmp(if_name,
                         pif->interfaces[i].if_name, IFNAMSIZ) == 0)) {
                // Found
                if (port_num) {
                    *port_num = i + 1;
                }
                return &pif->interfaces[i];
            }
        }
    } else if (if_index) {      // only if_index given
        for (i = 0; i < pif->num_interfaces; i++) {
            if (*if_index == pif->interfaces[i].if_index) {
                // Found
                if (port_num) {
                    *port_num = i + 1;
                }
                return &pif->interfaces[i];
            }
        }
    } else if (if_name) {       // only if_name given
        for (i = 0; i < pif->num_interfaces; i++) {
            if (strncmp(if_name,
                        pif->interfaces[i].if_name, IFNAMSIZ) == 0) {
                // Found
                if (port_num) {
                    *port_num = i + 1;
                }
                return &pif->interfaces[i];
            }
        }

    }
    return NULL;
}

/**
* Check if interface configuration exists. 
* @param ifr_name interface name
* @return -1 if disabled, otherwise index to ptp_cfg.interfaces[]
*/
static int if_configured(char *if_name)
{
    int i = 0;

    // check interface list
    for (i = 0; i < ptp_cfg.num_interfaces; i++) {
        if (strncmp(ptp_cfg.interfaces[i].name, if_name,
                    MIN(IFNAMSIZ, INTERFACE_NAME_LEN)) == 0) {
            DEBUG("interface %s configuration found\n",
                  ptp_cfg.interfaces[i].name);
            return i;
        }
    }
    return -1;
}
