/**
 * @file net.c
 * @brief Network and protocol interface
 * @author Adam Bruce
 * @date 12 Feb 2021
 */

#include "net.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

/**
 * @brief the local sending socket.
 */
static socket_t socket_send;

/**
 * @brief the local receiving socket.
 */
static socket_t socket_recv;

int get_local_address(char* buffer)
{
  struct ifaddrs *interfaces = NULL, *addr = NULL;
  void *addr_ptr = NULL;
  char addr_str[INET_ADDRSTRLEN];

  if(getifaddrs(&interfaces) != 0)
    {
      return 1;
    }

  for(addr = interfaces; addr != NULL; addr = addr->ifa_next)
    {
      if(addr->ifa_addr->sa_family == AF_INET && strstr(addr->ifa_name, "wla"))
	{
	  addr_ptr = &((struct sockaddr_in*)addr->ifa_addr)->sin_addr;
	  	 inet_ntop(addr->ifa_addr->sa_family,
			   addr_ptr,
			   addr_str,
			   sizeof(addr_str));
	  
		 strcpy(buffer, addr_str);
			  
	  break;
	} 
    }
  freeifaddrs(interfaces);
  return 0;
}

int init_net(void)
{
  if(init_sockets() != 0)
    {
      return 1;
    }
  if((socket_send = create_socket()) == 0)
    {
      return 1;
    }
  if(bind_socket(socket_send, PORT_SEND) != 0)
    {
      return 1;
    }
  if((socket_recv = create_socket()) == 0)
    {
      return 1;
    }
  if(bind_socket(socket_recv, PORT_RECV) != 0)
    {
      return 1;
    }
  return 0;
}

int cleanup_net(void)
{
  close_socket(socket_send);
  close_socket(socket_recv);
  return cleanup_sockets();
}

int send_to_host(char* ip_address, void* message, size_t length)
{
  struct sockaddr_in remote_addr;
  
  remote_addr.sin_family = AF_INET;
  remote_addr.sin_addr.s_addr = inet_addr(ip_address);
  remote_addr.sin_port = htons(PORT_RECV);

  return send_to_socket(socket_send, message, length, 0, remote_addr);
}

int send_advertisement_message(AdvertisementMessage *message)
{
  char buffer[10];
  struct in_addr addr;
  int status;
  
  buffer[0] = (message->type << 4);
  buffer[0] |= message->advertisement_type;
  buffer[1] = message->hops;

  status = inet_aton(message->source_addr, &addr);
  if(status == 0)
    {
      return 1;
    }
  memcpy(buffer + 2, &addr.s_addr, sizeof(addr.s_addr));

  status = inet_aton(message->target_addr, &addr);
  if(status == 0)
    {
      return 1;
    }
  memcpy(buffer + 6, &addr.s_addr, sizeof(addr.s_addr));
  
  return send_to_host(message->target_addr, (void*)buffer, sizeof(buffer));
}

int recv_advertisement_message(void* buffer)
{
  AdvertisementMessage message;
  char* char_buffer;

  struct sockaddr_in target, source;
  char source_str[INET_ADDRSTRLEN], target_str[INET_ADDRSTRLEN];

  char_buffer = (char*)buffer;
  message.type = char_buffer[0];
  message.advertisement_type = (char_buffer[0] & 0x0F);
  message.hops = char_buffer[1];

  source.sin_addr.s_addr = *(int*)(char_buffer + 2);
  target.sin_addr.s_addr = *(int*)(char_buffer + 6);
  inet_ntop(AF_INET, &source.sin_addr, source_str, sizeof(source_str));
  inet_ntop(AF_INET, &target.sin_addr, target_str, sizeof(target_str));

  printf("Source: %s\n", source_str);
  printf("Target: %s\n", target_str);
  return 0;
}

int poll_message(void *buffer, size_t length)
{
  int bytes_read;
  
  bytes_read = recv_from_socket(socket_recv, buffer, length, 0);
  switch(((char*)buffer)[0] & 0xF0)
    {
    case 0x0:
      return recv_advertisement_message(buffer);
      break;
    default:
      return bytes_read;
    }
}
