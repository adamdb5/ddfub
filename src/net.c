/**
 * @file net.c
 * @brief Network and protocol interface
 * @author Adam Bruce
 * @date 12 Feb 2021
 */

#include "net.h"

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/**
 * @brief the local sending socket.
 */
static socket_t socket_send;

/**
 * @brief the local receiving socket.
 */
static socket_t socket_recv;

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
  remote_addr.sin_port =  htons(PORT_RECV);

  return send_to_socket(socket_send, message, length, 0, remote_addr);
}

int poll_message(void *buffer, size_t length)
{
  return recv_from_socket(socket_recv, buffer, length, 0);
}
