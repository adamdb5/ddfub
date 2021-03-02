/**
 * @file socket.c
 * @brief Cross-platform socket interface.
 * @author Adam Bruce
 * @date 15 Dec 2020
 */

#include "socket.h"

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501 /* Patch for older NT kernels */
#endif
#include <io.h>
#include <winsock2.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif


int init_sockets(void)
{
#ifdef _WIN32
	WSADATA wsa_data;
	return WSAStartup(MAKEWORD(1,1), &wsa_data);
#else
	return 0;
#endif
}

int cleanup_sockets(void)
{
#ifdef _WIN32
	return WSACleanup();
#else
	return 0;
#endif
}

socket_t create_socket(void)
{
	socket_t sock;
#ifdef _WIN32
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#else
	sock = socket(AF_INET, SOCK_DGRAM, 0);
#endif
	return sock;
}

void close_socket(socket_t sock)
{
#ifdef _WIN32
	closesocket(sock);
#else
	close(sock);
#endif
}

int bind_socket(socket_t sock, int port)
{
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);
	
	return bind(sock, (struct sockaddr*)&addr, sizeof(addr));
}

int send_to_socket(socket_t sock, void* message, size_t length, int flags,
                   struct sockaddr_in dest_addr)
{
	return sendto(sock, message, length, flags, (struct sockaddr*)&dest_addr, 
	              sizeof(dest_addr));
}

int recv_from_socket(socket_t sock, void* buffer, size_t length, int flags)
{
	return recv(sock, buffer, length, flags);
}
