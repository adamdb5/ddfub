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

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#endif

#define ETH_PREFIX_LEN 5

/**
 * @brief the local sending socket.
 */
static socket_t socket_send;

/**
 * @brief the local receiving socket.
 */
static socket_t socket_recv;

/** 
 * @brief the list of known hosts.
 */
static HostList* host_list;

/**
 * @brief the local IP address.
 */
static char local_address[INET_ADDRSTRLEN];

/** 
 * @brief known ethernet adapter prefixes.
 *
 * Used for obtaining the assigned ethernet address.
 */
static char eth_prefixes[6][ETH_PREFIX_LEN + 1] = {
  "eth", "em", "ed", "genet", "usmsc", "\0"
};


#ifdef _WIN32
#define ADAPTER_NAME_LEN 8
int get_local_address(char* buffer)
{
  printf("[ INFO ] Retrieving adapter information\n");
  DWORD rv, size;
  PIP_ADAPTER_ADDRESSES adapter_addresses, aa;
  PIP_ADAPTER_UNICAST_ADDRESS ua;
  char address[INET_ADDRSTRLEN], name[ADAPTER_NAME_LEN];
  
  rv = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &size);
  if (rv != ERROR_BUFFER_OVERFLOW)
    {
      return 1;
    }
  adapter_addresses = (PIP_ADAPTER_ADDRESSES)malloc(size);
  
  rv = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, adapter_addresses, &size);
  if (rv != ERROR_SUCCESS)
    {
      free(adapter_addresses);
      return 1;
    }
  
  for (aa = adapter_addresses; aa != NULL; aa = aa->Next)
    {
      memset(name, '\0', ADAPTER_NAME_LEN);      
      WideCharToMultiByte(CP_ACP, 0, aa->FriendlyName, wcslen(aa->FriendlyName), name, ADAPTER_NAME_LEN,
			  NULL, NULL);

      if(strncmp(name, "Ethernet", ADAPTER_NAME_LEN) == 0)
	{
	  for (ua = aa->FirstUnicastAddress; ua != NULL; ua = ua->Next)
	    {
	      memset(address, '\0', INET_ADDRSTRLEN);
	      getnameinfo(ua->Address.lpSockaddr, ua->Address.iSockaddrLength, address, INET_ADDRSTRLEN,
			  NULL, 0, NI_NUMERICHOST);

	      strncpy(buffer, address, INET_ADDRSTRLEN);
	      free(adapter_addresses);
	      return 0;
	    }
	}
    }
  
  free(adapter_addresses);
  return 1;
}
#else
int get_local_address(char* buffer)
{
  printf("[ INFO ] Retrieving adapter information\n");
  struct ifaddrs *interfaces = NULL, *addr = NULL;
  void *addr_ptr = NULL;
  char addr_str[INET_ADDRSTRLEN];
  int prefix_index, match;
  
  if(getifaddrs(&interfaces) != 0)
    {
      return 1;
    }

  match = 0;
  for(addr = interfaces; addr != NULL; addr = addr->ifa_next)
    {
      if(addr->ifa_addr->sa_family == AF_INET)
	{
	  prefix_index = 0;
	  match = 0;
	  while(eth_prefixes[prefix_index][0] != '\0')
	    {
	      if(strstr(addr->ifa_name, eth_prefixes[prefix_index]))
		{
		  match = 1;
		  break;
		}
	      prefix_index++;
	    }
	}

      if(match)
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
  return !match;
}
#endif

int load_hosts_from_file(const char *fname)
{
  printf("[ INFO ] Loading known hosts from file.\n");
  FILE *file;
  size_t len, read;
  char buffer[INET_ADDRSTRLEN], *newline_ptr;
  HostList *host;

  if(!host_list)
    {
      printf("Network stack not yet initialised!\n");
      return 1;
    }
  
  file = fopen(fname, "r");
  if(!file)
    {
      printf("File %s does not exist\n", fname);
      return 1;
    }

  len = 0;
  read = 0;
  memset(buffer, '\0', INET_ADDRSTRLEN);

  while((read = fread(buffer + len, 1, 1, file)))
    {
      if(buffer[0] == '\r' || buffer[0] == '\n'){
	buffer[0] = '\0';
	len = 0;
	continue;
      }

      len++;
      newline_ptr = strpbrk(buffer, "\r\n");
      if(newline_ptr)
	{
	  buffer[len - 1] = '\0';

	  if(strlen(host_list->addr) == 0)
	    {
	      strncpy(host_list->addr, buffer, INET_ADDRSTRLEN);
	    }
	  else
	    {
	      host = host_list;
	      while(host && host->next)
		{
		  host = host->next;
		}

	      host->next = (HostList*)malloc(sizeof(HostList));
	      memset(host->next, 0, sizeof(HostList));
	      strncpy(host->next->addr, buffer, INET_ADDRSTRLEN);
	    }
	  
	  memset(buffer, '\0', INET_ADDRSTRLEN);
	  len = 0;
	}
    }

  fclose(file);
  return 0;
}

int add_host(char *addr)
{
  printf("[ INFO ] Adding new host (%s).\n", addr);
  HostList *host;

  if(!host_list)
    {
      return 1;
    }
  if(!addr)
    {
      return 1;
    }

  host = host_list;
  if(strlen(host->addr) == 0)
    {
      strncpy(host->addr, addr, INET_ADDRSTRLEN);
    }
  else
    {
      while(host && host->next)
	{
	  host = host->next;
	}

      host->next = (HostList*)malloc(sizeof(HostList));
      memset(host->next, 0, sizeof(HostList));
      strncpy(host->next->addr, addr, INET_ADDRSTRLEN);
    }

  return 0;
}

int print_hosts(void)
{
  HostList *host;
  host = host_list;
  
  if(host)
    {
      while(host)
	{
	  printf("Host: %s\n", host->addr);
	  host = host->next;
	}
      
    }
  return 0;
}

int check_host_exists(char *addr)
{
  printf("[ INFO ] Checking if %s is already known.\n", addr);
  HostList *host;

  host = host_list;
  if(!host)
    {
      printf("Network stack not yet initialised!\n");
      return 0;
    }
  if(!addr)
    {
      return 0;
    }

  while(host)
    {
      if(strncmp(addr, host->addr, INET_ADDRSTRLEN) == 0)
	{
	  return 1;
	}
      host = host->next;
    }

  return 0;
}

int init_net(void)
{
  printf("[ INFO ] Initiating network API.\n");
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

  if(get_local_address(local_address) != 0)
    {
      return 1;
    }

  host_list = (HostList*)malloc(sizeof(HostList));
  if(!host_list)
    {
      return 1;
    }
  memset(host_list, 0, sizeof(HostList));
  
  return 0;
}

int cleanup_net(void)
{
  printf("[ INFO ] Cleaning up network API.\n");
  /* TODO: Writeback host_list */
  HostList *host, *temp;
  host = host_list;
  
  while(host)
    {
      temp = host;
      host = host->next;
      free(temp);
    }
  
  close_socket(socket_send);
  close_socket(socket_recv);
  return cleanup_sockets();
}

int send_to_host(char* ip_address, void* message, size_t length)
{
  printf("[ INFO ] Sending message of length %zu to %s.\n", length, ip_address);
  struct sockaddr_in remote_addr;
  
  remote_addr.sin_family = AF_INET;
  remote_addr.sin_addr.s_addr = inet_addr(ip_address);
  remote_addr.sin_port = htons(PORT_RECV);

  return send_to_socket(socket_send, message, length, 0, remote_addr);
}

int send_advertisement_message(AdvertisementMessage *message)
{
  printf("[ INFO ] Sending advertisement message.\n");
  char buffer[11];
  struct in_addr addr;
  int status;
  
  buffer[0] = message->type;
  buffer[1] = message->hops;
  buffer[2] = message->advertisement_type;

  status = inet_pton(AF_INET, message->source_addr, &addr);
  if(status == 0)
    {
      return 1;
    }
  memcpy(buffer + 3, &addr.s_addr, sizeof(addr.s_addr));

  status = inet_pton(AF_INET, message->target_addr, &addr);
  if(status == 0)
    {
      return 1;
    }
  memcpy(buffer + 7, &addr.s_addr, sizeof(addr.s_addr));
  
  return send_to_host(message->next_addr, (void*)buffer, sizeof(buffer));
}

int recv_advertisement_message(void* buffer)
{
  printf("[ INFO ] Received advertisement message.\n");
  AdvertisementMessage message;
  char* char_buffer;

  struct sockaddr_in target, source;

  char_buffer = (char*)buffer;
  message.type = char_buffer[0];
  message.hops = char_buffer[1];
  message.advertisement_type = char_buffer[2];

  source.sin_addr.s_addr = *(int*)(char_buffer + 3);
  target.sin_addr.s_addr = *(int*)(char_buffer + 7);
  inet_ntop(AF_INET, &source.sin_addr, message.source_addr, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &target.sin_addr, message.target_addr, INET_ADDRSTRLEN);

  switch(message.advertisement_type)
    {
    case BROADCAST:
      recv_advertisement_broadcast(&message);
      break;
    case ACK:
      recv_advertisement_ack(&message);
      break;
    }
  
  printf("Source: %s\n", message.source_addr);
  printf("Target: %s\n", message.target_addr);
  
  return 0;
}

int recv_advertisement_broadcast(AdvertisementMessage *message)
{
  printf("Received ADVERTISEMENT::BROADCAST\n");
  AdvertisementMessage new_message;
  HostList *host;
  
  if(!message)
    {
      return 1;
    }
  
  printf("local_addr: %s\n", local_address);
  printf("message->target_addr: %s\n", message->target_addr);

  /* If new host, add */
  if(!check_host_exists(message->source_addr))
    {
      add_host(message->source_addr);
      new_message.type = ADVERTISEMENT;
      new_message.hops = 0;
      new_message.advertisement_type = ACK;
      strncpy(new_message.source_addr, local_address, INET_ADDRSTRLEN);
      strncpy(new_message.target_addr, message->source_addr, INET_ADDRSTRLEN);

      /* Send ACK */
      host = host_list;
      while(host)
	{
	  strncpy(new_message.next_addr, host->addr, INET_ADDRSTRLEN);
	  send_advertisement_message(&new_message);
	  host = host->next;
	}
    }

  /* If under max hop count, forward to all hosts */
  if(message->hops < MAX_ADVERTISEMENT_HOPS)
    {
      host = host_list;
      if(host)
	{
	  memcpy(&new_message, message, sizeof(AdvertisementMessage));
	  new_message.hops++;
	  
	  while(host)
	    {
	      strncpy(new_message.next_addr, host->addr, INET_ADDRSTRLEN);
	      send_advertisement_message(&new_message);
	      host = host->next;
	    }     
	}
    }
  
  return 0;
}

int recv_advertisement_ack(AdvertisementMessage* message)
{
  printf("Received ADVERTISEMENT::ACK\n");
  HostList *host;
  
  if(!message)
    {
      return 1;
    }

  /* Check if we are the intended recipient */
  if(strncmp(local_address, message->target_addr, INET_ADDRSTRLEN) == 0
     && !check_host_exists(message->source_addr))
    {
      add_host(message->source_addr);
    }
  else
    {
      if(message->hops < MAX_ADVERTISEMENT_HOPS)
	{
	  host = host_list;
	  message->hops++;

	  while(host)
	    {
	      strncpy(message->next_addr, host->addr, INET_ADDRSTRLEN);
	      send_advertisement_message(message);
	      host = host->next;
	    }
	}
    }
  
  return 0;
}

int poll_message(void *buffer, size_t length)
{
  printf("[ INFO ] Polling for message.\n");
  int bytes_read;
  
  bytes_read = recv_from_socket(socket_recv, buffer, length, 0);
  switch(((char*)buffer)[0])
    {
    case ADVERTISEMENT:
      return recv_advertisement_message(buffer);
      break;
    default:
      return bytes_read;
    }
}
