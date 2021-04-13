/**
 * @file net.c
 * @brief Network and protocol interface
 * @author Adam Bruce
 * @date 22 Mar 2021
 */

#include "net.h"
#include "blockchain.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <openssl/sha.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#undef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#endif

/**
 * @brief The maximum length of a *nix ethernet adapter prefix.
 */ 
#define ETH_PREFIX_LEN 5

/**
 * @brief The local sending socket.
 */
static socket_t socket_send;

/**
 * @brief The local receiving socket.
 */
static socket_t socket_recv;

/** 
 * @brief The list of known hosts.
 */
static HostList *host_list;

#ifndef _WIN32
/** 
 * @brief Known ethernet adapter prefixes.
 *
 * Used for obtaining the assigned ethernet address.
 */
static char eth_prefixes[6][ETH_PREFIX_LEN + 1] = {
  "eth", "em", "ed", "genet", "usmsc", "\0"
};
#endif


#ifdef _WIN32
#define ADAPTER_NAME_LEN 8
int get_local_address(char* buffer)
{
  DWORD rv, size;
  PIP_ADAPTER_ADDRESSES adapter_addresses, aa;
  PIP_ADAPTER_UNICAST_ADDRESS ua;
  char address[INET_ADDRSTRLEN], name[ADAPTER_NAME_LEN];

  rv = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL,
			    &size);
  if (rv != ERROR_BUFFER_OVERFLOW)
    {
      return 1;
    }
  adapter_addresses = (PIP_ADAPTER_ADDRESSES)malloc(size);
  
  rv = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL,
			    adapter_addresses, &size);
  if (rv != ERROR_SUCCESS)
    {
      free(adapter_addresses);
      return 1;
    }
  
  for (aa = adapter_addresses; aa != NULL; aa = aa->Next)
    {
      memset(name, '\0', ADAPTER_NAME_LEN);      
      WideCharToMultiByte(CP_ACP, 0, aa->FriendlyName,
			  wcslen(aa->FriendlyName), name, ADAPTER_NAME_LEN,
			  NULL, NULL);

      if(strncmp(name, "Ethernet", ADAPTER_NAME_LEN) == 0)
	{
	  for (ua = aa->FirstUnicastAddress; ua != NULL; ua = ua->Next)
	    {
	      memset(address, '\0', INET_ADDRSTRLEN);
	      getnameinfo(ua->Address.lpSockaddr, ua->Address.iSockaddrLength,
			  address, INET_ADDRSTRLEN, NULL, 0, NI_NUMERICHOST);

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
int get_local_address(char *buffer)
{
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

int get_acks(void)
{
  HostList *host;
  int count;
  
  host = host_list;
  if(!host || strlen(host->addr) == 0)
    {
      return 0;
    }

  count = 0;
  while(host)
    {
      if(host->ack > 0)
	{
	  count++;
	}
      host = host->next;
    }

  return count;
}

int reset_acks(void)
{
  HostList *host;
  
  host = host_list;
  if(!host || strlen(host->addr) == 0)
    {
      return 1;
    }
  
  while(host)
    {
      host->ack = 0;
      host = host->next;
    }

  return 0;
}

int set_ack(char *addr)
{
  HostList *host;
  
  host = host_list;
  if(!host || strlen(host->addr) == 0)
    {
      return 1;
    }
  
  while(host)
    {
      if(strncmp(host->addr, addr, INET_ADDRSTRLEN) == 0)
	{
	  host->ack = 1;
	  return 0;
	}
      host = host->next;
    }

  return 1;
}

int load_hosts_from_file(const char *fname)
{
  FILE *file;
  int c;
  size_t pos;
  char buffer[INET_ADDRSTRLEN + 10];
  
  if(!host_list)
    {
      printf("[ ERR  ] Network stack not yet initialised\n");
      return 1;
    }
  
  file = fopen(fname, "r");
  if(!file)
    {
      printf("[ NET  ] No hostfile found\n");
      return 1;
    }

  pos = 0;
  while((c = fgetc(file)) != EOF)
    {
      if((char)c == '\r')
	{
	  continue;
	}

      if((char)c == '\n')
	{
	  buffer[pos] = '\0';
	  add_host(buffer);
	  memset(buffer, '\0', INET_ADDRSTRLEN + 10);
	  pos = 0;
	  continue;
	}

      buffer[pos++] = (char)c;
    }

  fclose(file);
  return 0;
}

int save_hosts_to_file(const char *fname)
{
  FILE *file;
  HostList *host;
  
  if(!host_list)
    {
      printf("[ ERR  ] Network stack not yet initialised\n");
      return 1;
    }
  
  file = fopen(fname, "w+");
  if(!file)
    {
      printf("[ ERR  ] Could not create hostfile\n");
      return 1;
    }

  host = host_list;
  if(host)
    {
      while(host && strlen(host->addr) > 0)
	{
	  fwrite(host->addr, strlen(host->addr), 1, file);
	  fputc('\n', file);
	  host = host->next;
	}
    }

  fclose(file);
  return 0;
}

int add_host(char *addr)
{
  HostList *host;

  printf("[ NET  ] Adding new host (%s)\n", addr);
  
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
  return save_hosts_to_file("hosts.txt");
}



int check_host_exists(char *addr)
{
  HostList *host;
  
  host = host_list;
  if(!host)
    {
      printf("[ ERR  ] Network stack not yet initialised\n");
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

int get_host_count(void)
{
  HostList *host;
  int count;
  
  host = host_list;
  if(!host || strlen(host->addr) == 0)
    {
      return 0;
    }

  count = 0;
  while(host)
    {
      count++;
      host = host->next;
    }

  return count;
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

int send_to_host(char *ip_address, void *message, size_t length)
{
  struct sockaddr_in remote_addr;

  remote_addr.sin_family = AF_INET;
  remote_addr.sin_addr.s_addr = inet_addr(ip_address);
  remote_addr.sin_port = htons(PORT_RECV);

  return send_to_socket(socket_send, message, length, 0, remote_addr);
}

int send_advertisement_message(AdvertisementMessage *message)
{
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

  status = inet_pton(AF_INET, message->next_addr, &addr);
  if(status == 0)
    {
      return 1;
    }
  memcpy(buffer + 7, &addr.s_addr, sizeof(addr.s_addr));
  
  return send_to_host(message->next_addr, (void*)buffer, sizeof(buffer));
}

int send_to_all_advertisement_message(AdvertisementMessage *message)
{
  HostList *host;
  host = host_list;
  while(host)
    {
      strncpy(message->next_addr, host->addr, INET_ADDRSTRLEN);
      send_advertisement_message(message);
      host = host->next;
    }
  return 0;
}

int recv_advertisement_message(void *buffer)
{
  AdvertisementMessage message;
  char *char_buffer;
  struct sockaddr_in target, source;
  
  char_buffer = (char*)buffer;
  message.type = char_buffer[0];
  message.hops = char_buffer[1];
  message.advertisement_type = char_buffer[2];

  source.sin_addr.s_addr = *(int*)(char_buffer + 3);
  target.sin_addr.s_addr = *(int*)(char_buffer + 7);
  inet_ntop(AF_INET, &source.sin_addr, message.source_addr, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &target.sin_addr, message.target_addr, INET_ADDRSTRLEN);

  if(strncmp(local_address, message.source_addr, INET_ADDRSTRLEN) == 0)
    {
      return 0;
    }
  
  switch(message.advertisement_type)
    {
    case BROADCAST:
      recv_advertisement_broadcast(&message);
      break;
    case ACK:
      recv_advertisement_ack(&message);
      break;
    }
  
  return 0;
}

int recv_advertisement_broadcast(AdvertisementMessage *message)
{
  AdvertisementMessage new_message;
  
  if(!message)
    {
      return 1;
    }
  
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
      send_to_all_advertisement_message(&new_message);
    }

  /* If under max hop count, forward to all hosts */
  if(message->hops < MAX_HOPS)
    {
      memcpy(&new_message, message, sizeof(AdvertisementMessage));
      new_message.hops++;
      send_to_all_advertisement_message(&new_message);
    }
  
  return 0;
}

int recv_advertisement_ack(AdvertisementMessage* message)
{
  AdvertisementMessage new_message;

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
      if(message->hops < MAX_HOPS)
	{
	  memcpy(&new_message, message, sizeof(AdvertisementMessage));
	  new_message.hops++;
	  send_to_all_advertisement_message(&new_message);
	}
    }
  
  return 0;
}

int send_consensus_message(ConsensusMessage *message)
{
  char buffer[11 + SHA256_DIGEST_LENGTH];
  char hash_string[SHA256_STRING_LENGTH + 1];
  struct in_addr addr;
  int status;
  
  buffer[0] = message->type;
  buffer[1] = message->hops;
  buffer[2] = message->consensus_type;

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

  
  memcpy(buffer + 11, message->last_block_hash, SHA256_DIGEST_LENGTH);
  get_hash_string(hash_string, message->last_block_hash,
		  SHA256_STRING_LENGTH + 1);
  
  return send_to_host(message->next_addr, (void*)buffer, sizeof(buffer));
}

int send_to_all_consensus_message(ConsensusMessage *message)
{
  HostList *host;
  host = host_list;
  while(host && strlen(host->addr) > 0)
    {
      strncpy(message->next_addr, host->addr, INET_ADDRSTRLEN);
      send_consensus_message(message);
      host = host->next;
    }
  return 0;
}
  
int recv_consensus_message(void *buffer)
{
  ConsensusMessage message;
  char *char_buffer;
  struct sockaddr_in target, source;
  
  char_buffer = (char*)buffer;
  message.type = char_buffer[0];
  message.hops = char_buffer[1];
  message.consensus_type = char_buffer[2];

  source.sin_addr.s_addr = *(int*)(char_buffer + 3);
  target.sin_addr.s_addr = *(int*)(char_buffer + 7);
  inet_ntop(AF_INET, &source.sin_addr, message.source_addr, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &target.sin_addr, message.target_addr, INET_ADDRSTRLEN);

  memcpy(message.last_block_hash, char_buffer + 11, SHA256_DIGEST_LENGTH);

  switch(message.consensus_type)
    {
    case BROADCAST:
      recv_consensus_broadcast(&message);
      break;
    case ACK:
      recv_consensus_ack(&message);
      break;
    }
  
  return 0;
}

int recv_consensus_broadcast(ConsensusMessage *message)
{
  ConsensusMessage new_message;
  unsigned char last_hash[SHA256_DIGEST_LENGTH];
  char hash_string[SHA256_STRING_LENGTH + 1];
  

  if(!message)
    {
      return 1;
    }

  /* We've just received our own broadcast, do nothing */
  if(strncmp(message->source_addr, local_address, INET_ADDRSTRLEN) == 0)
    {
      return 0;
    }

  get_hash_string(hash_string, message->last_block_hash,
		  SHA256_STRING_LENGTH + 1);
   
  /* If hashes match, add to pending_rules */
  get_last_hash(last_hash);
  if(memcmp(last_hash, "\0", 1) == 0 ||
     memcmp(message->last_block_hash, last_hash, SHA256_DIGEST_LENGTH) == 0)
    {
      if(!is_pending(message->source_addr))
	{
	  printf("[ CONS ] Received consensus message with matching hash\n");
	  add_pending_rule(message->source_addr);
	  new_message.type = CONSENSUS;
	  new_message.hops = 0;
	  new_message.consensus_type = ACK;
	  strncpy(new_message.source_addr, local_address, INET_ADDRSTRLEN);
	  strncpy(new_message.target_addr, message->source_addr, INET_ADDRSTRLEN);
	  memcpy(new_message.last_block_hash, message->last_block_hash,
		 SHA256_DIGEST_LENGTH);
	  send_to_all_consensus_message(&new_message);
	}

    }
  else
    {
      printf("[ CONS ] Received consensus message with mismatched hash\n");
    }

  /* If under max hop count, forward to all hosts */
  if(message->hops < MAX_HOPS)
    {
      memcpy(&new_message, message, sizeof(ConsensusMessage));
      new_message.hops++;
      send_to_all_consensus_message(&new_message);
    }
  
  return 0;
}

int recv_consensus_ack(ConsensusMessage *message)
{
  ConsensusMessage new_message;
  
  if(!message)
    {
      return 1;
    }

  /* Check if we are the intended recipient */
  if(strncmp(local_address, message->target_addr, INET_ADDRSTRLEN) == 0)
    {
      set_ack(message->source_addr);
    }
  else
    {
      if(message->hops < MAX_HOPS)
	{
	  memcpy(&new_message, message, sizeof(ConsensusMessage));
	  new_message.hops++;
	  send_to_all_consensus_message(&new_message);
	}
    }
  
  return 0;
}

int send_rule_message(RuleMessage *message)
{
  char buffer[11 + 4 + 4 + 2 + 2 + 4];
  struct in_addr addr;
  int status;
  
  buffer[0] = message->type;
  buffer[1] = message->hops;
  buffer[2] = message->rule_type;
  
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

  status = inet_pton(AF_INET, (void*)&message->rule.source_addr, &addr);
  if(status == 0)
    {
      return 1;
    }
  memcpy(buffer + 11, &addr.s_addr, sizeof(addr.s_addr));

  status = inet_pton(AF_INET, (void*)&message->rule.dest_addr, &addr);
  if(status == 0)
    {
      return 1;
    }
  memcpy(buffer + 15, &addr.s_addr, sizeof(addr.s_addr));

  memcpy(buffer + 19, (void*)&message->rule.source_port, 2);
  memcpy(buffer + 21, (void*)&message->rule.dest_port, 2);
  memcpy(buffer + 23, (void*)&message->rule.action, 4);

  return send_to_host(message->next_addr, (void*)buffer, sizeof(buffer));
}

int send_to_all_rule_message(RuleMessage *message)
{
  HostList *host;
  host = host_list;
  while(host)
    {
      strncpy(message->next_addr, host->addr, INET_ADDRSTRLEN);
      send_rule_message(message);
      host = host->next;
    }
  return 0;
}

int recv_rule_message(void *buffer)
{
  RuleMessage message;
  char *char_buffer;
  struct sockaddr_in target, source, fw_source, fw_dest;

  memset(&message, '\0', sizeof(RuleMessage));
  char_buffer = (char*)buffer;
  message.type = char_buffer[0];
  message.hops = char_buffer[1];
  message.rule_type = char_buffer[2];

  source.sin_addr.s_addr = *(int*)(char_buffer + 3);
  target.sin_addr.s_addr = *(int*)(char_buffer + 7);
  inet_ntop(AF_INET, &source.sin_addr, message.source_addr, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &target.sin_addr, message.target_addr, INET_ADDRSTRLEN);

  fw_source.sin_addr.s_addr = *(int*)(char_buffer + 11);
  fw_dest.sin_addr.s_addr = *(int*)(char_buffer + 15);
  inet_ntop(AF_INET, &fw_source.sin_addr, message.rule.source_addr,
	    INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &fw_dest.sin_addr, message.rule.dest_addr,
	    INET_ADDRSTRLEN);

  memcpy(&message.rule.source_port, (uint16_t*)(char_buffer + 19), 2);
  memcpy(&message.rule.dest_port, (uint16_t*)(char_buffer + 21), 2);
  memcpy(&message.rule.action, (int*)(char_buffer + 23), 4);
  
  switch(message.rule_type)
    {
    case BROADCAST:
      recv_rule_broadcast(&message);
      break;
    case ACK:
      break;
    }
  
  return 0;
}

int recv_rule_broadcast(RuleMessage *message)
{
  FirewallBlock new_block;
  unsigned char last_hash[SHA256_DIGEST_LENGTH];
  RuleMessage new_message;
  
  if(!message)
    {
      return 1;
    }
  
  if(is_pending(message->source_addr))
    {
      get_last_hash(last_hash);
      memset(&new_block, '\0', sizeof(FirewallBlock));
      memcpy(new_block.last_hash, last_hash, SHA256_DIGEST_LENGTH);
      strncpy(new_block.author, message->source_addr, INET_ADDRSTRLEN);
      memcpy(&new_block.rule, &message->rule, sizeof(FirewallRule));
      add_block_to_chain(&new_block);
      recv_new_rule(&new_block.rule);

      remove_pending_rule(message->source_addr);
    }

  /* If under max hop count, forward to all hosts */
  if(message->hops < MAX_HOPS)
    {
      memcpy(&new_message, message, sizeof(RuleMessage));
      new_message.hops++;
      send_to_all_rule_message(&new_message);
    }
  
  return 0;
}

int poll_message(void *buffer, size_t length)
{
  int bytes_read;

  bytes_read = recv_from_socket(socket_recv, buffer, length, 0);
  if(bytes_read <= 0)
    {
      return 0;
    }
    
  switch(((char*)buffer)[0])
    {
    case ADVERTISEMENT:
      return recv_advertisement_message(buffer);
      break;
    case CONSENSUS:
      return recv_consensus_message(buffer);
      break;
    case RULE:
      return recv_rule_message(buffer);
      break;
    default:
      return bytes_read;
    }
}
