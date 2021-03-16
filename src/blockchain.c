/**
 * @file blockchain.c
 * @brief Functions for creating and validating blockchains.
 * @author Adam Bruce
 * @date 03 Feb 2021
 */

#include "blockchain.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/sha.h>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#define PENDING_RULES_BUF_LEN 10
static char pending_rules[PENDING_RULES_BUF_LEN][INET_ADDRSTRLEN];

int get_block_hash(unsigned char* buffer, FirewallBlock *block, int buffer_size)
{
  SHA256_CTX sha256;
  
  if(buffer_size < SHA256_DIGEST_LENGTH || !buffer || !block)
    {
      return 1;
    }

  SHA256_Init(&sha256);
  SHA256_Update(&sha256, block, sizeof(FirewallBlock));
  SHA256_Final(buffer, &sha256);
 
  return 0;
}

int get_hash_string(char* buffer, unsigned char* hash, int buffer_size)
{
  int i;

  if(buffer_size < SHA256_STRING_LENGTH + 1 || !buffer || !hash)
    {
      return 1;
    }

  for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
      sprintf(buffer + (i * 2), "%02x", hash[i]);
    }
  hash[SHA256_STRING_LENGTH] = '\0';
  return 0;
}

int add_block_to_chain(FirewallBlock *block)
{
  FirewallBlock *fw_chain;
  
  if(!chain)
    {
      fw_chain = (FirewallBlock*)malloc(sizeof(FirewallBlock));
      memcpy(chain, fw_chain, sizeof(FirewallBlock));
      return 0;
    }

  fw_chain = chain;
  while(fw_chain && fw_chain->next)
    {
      fw_chain = fw_chain->next;
    }

  fw_chain->next = (FirewallBlock*)malloc(sizeof(FirewallBlock));
  memcpy(fw_chain->next, block, sizeof(FirewallBlock));
  return 0;
  
}

int rotate_pending_rules(void)
{
  int index;

  for(index = 0; index < PENDING_RULES_BUF_LEN - 2; index++)
    {
      strncpy(pending_rules[index], pending_rules[index + 1], INET_ADDRSTRLEN);
    }
  memset(pending_rules[0], '\0', INET_ADDRSTRLEN);

  return 0;
}

int add_pending_rule(char *addr)
{
  rotate_pending_rules();
  strncpy(pending_rules[0], addr, INET_ADDRSTRLEN);
  return 0;
}

int is_pending(char *addr)
{
  int index;

  for(index = 0; index < PENDING_RULES_BUF_LEN; index++)
    {
      if(strncmp(pending_rules[index], addr, INET_ADDRSTRLEN) == 0)
	{
	  return 1;
	}
    }
  return 0;
}

int remove_pending_rule(char *addr)
{
  int index, match;

  match = 0;
  for(index = 0; index < PENDING_RULES_BUF_LEN; index++)
    {
      if(strncmp(pending_rules[index], addr, INET_ADDRSTRLEN) == 0)
	{
	  match = 1;
	  break;
	}
    }

  if(match)
    {
      for(; index > 0; index--)
	{
	  strncpy(pending_rules[index], pending_rules[index - 1], INET_ADDRSTRLEN);
	}
      memset(pending_rules[0], '\0', INET_ADDRSTRLEN);
    }

  return 0;
}

int get_last_hash(unsigned char *buffer)
{
   FirewallBlock *fw_chain;
  
  if(!chain)
    {
      memset(buffer, '\0', SHA256_DIGEST_LENGTH);
      return 0;
    }

  fw_chain = chain;
  while(fw_chain && fw_chain->next)
    {
      fw_chain = fw_chain->next;
    }

  get_block_hash(buffer, fw_chain, SHA256_DIGEST_LENGTH);
  return 0;
}
