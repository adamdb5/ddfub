/**
 * @file socket.c
 * @brief Cross-platform socket interface.
 * @author Adam Bruce
 * @date 15 Dec 2020
 */

#include "socket.h"
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#include <io.h>
#include <winsock2.h>
#else
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif


int init_sockets(void)
{
#ifdef _WIN32
  WSADATA wsa_data;
#endif
  printf("[ INFO ] Setting up sockets.\n");
#ifdef _WIN32
  return WSAStartup(MAKEWORD(1,1), &wsa_data);
#else
  return 0;
#endif
}

int cleanup_sockets(void)
{
  printf("[ INFO ] Cleaning up sockets.\n");
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
  DWORD ival;
  #else
  struct timeval tv;
  #endif
  
  printf("[ INFO ] Creating new socket.\n");
#ifdef _WIN32
    ival = 1000;
  sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&ival, sizeof(DWORD));
#else
  memset(&tv, 0, sizeof(struct timeval));
  tv.tv_sec = 1;
  sock = socket(AF_INET, SOCK_DGRAM, 0);
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));
#endif
  return sock;
}

void close_socket(socket_t sock)
{
  printf("[ INFO ] Closing socket.\n");
#ifdef _WIN32
  closesocket(sock);
#else
  close(sock);
#endif
}

int bind_socket(socket_t sock, int port)
{
  struct sockaddr_in addr;
  printf("[ INFO ] Binding socket. \n");
  
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);
 
  return bind(sock, (struct sockaddr*)&addr, sizeof(addr));
}

int send_to_socket(socket_t sock, void *message, size_t length, int flags,
                   struct sockaddr_in dest_addr)
{
  printf("[ INFO ] Sending message of length %zu to socket.\n", length);
  return sendto(sock, message, length, flags, (struct sockaddr*)&dest_addr, 
		sizeof(dest_addr));
}

int recv_from_socket(socket_t sock, void *buffer, size_t length, int flags)
{
  /* printf("[ INFO ] Attempting to read %zu bytes from socket.\n", length); */
  return recv(sock, buffer, length, flags);
}
