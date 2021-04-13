/**
 * @file blockchain.c
 * @brief Functions for creating and validating blockchains.
 * @author Adam Bruce
 * @date 22 Mar 2021
 */

#include "blockchain.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/sha.h>

#ifdef _WIN32
#include <ws2tcpip.h>
#undef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#else
#include <arpa/inet.h>
#endif

#define PENDING_RULES_BUF_LEN 10
static char pending_rules[PENDING_RULES_BUF_LEN][INET_ADDRSTRLEN];

int get_block_hash(unsigned char *buffer, FirewallBlock *block,
		   int buffer_size)
{
  SHA256_CTX sha256;
  unsigned char data_to_hash[(INET_ADDRSTRLEN * 3) + 8];
  
  if(buffer_size < SHA256_DIGEST_LENGTH || !buffer || !block)
    {
      return 1;
    }

  memcpy(data_to_hash, block->author, INET_ADDRSTRLEN);
  memcpy(data_to_hash + INET_ADDRSTRLEN, block->rule.source_addr,
	 INET_ADDRSTRLEN);
  memcpy(data_to_hash + INET_ADDRSTRLEN * 2, block->rule.dest_addr,
	 INET_ADDRSTRLEN);
  memcpy(data_to_hash + INET_ADDRSTRLEN * 3,
	 (void*)&block->rule.source_port, 2);
  memcpy(data_to_hash + (INET_ADDRSTRLEN * 3) + 2,
	 (void*)&block->rule.dest_port, 2);
  memcpy(data_to_hash + (INET_ADDRSTRLEN * 3) + 4,
	 (void*)&block->rule.action, 4);

  SHA256_Init(&sha256);
  SHA256_Update(&sha256, data_to_hash, (INET_ADDRSTRLEN * 3) + 4 + 4);
  SHA256_Final(buffer, &sha256);
 
  return 0;
}

int get_hash_string(char *buffer, unsigned char *hash, int buffer_size)
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
  buffer[SHA256_STRING_LENGTH] = '\0';
  return 0;
}

int get_hash_from_string(unsigned char *buffer, char *hash_string,
			 int buffer_size)
{
  int i;
  uint16_t hex_val;
  char buf[3];

  if(buffer_size < SHA256_DIGEST_LENGTH || !buffer || !hash_string)
    {
      return 1;
    }

  buf[2] = '\0';
  for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
      memcpy(buf, hash_string + (i * 2), 2);
      hex_val = strtol(buf, NULL, 16);
      memcpy(buffer + i, &hex_val, 2);
    }

  return 0;
}

int add_block_to_chain(FirewallBlock *block)
{
  FirewallBlock *fw_chain;
  unsigned char hash[SHA256_DIGEST_LENGTH + 1];
  char hash_string[SHA256_STRING_LENGTH + 1];

  get_block_hash(hash, block, SHA256_DIGEST_LENGTH + 1);
  get_hash_string(hash_string, hash, SHA256_STRING_LENGTH + 1);
  hash_string[9] = '\0';
  
  if(!chain)
    {
      chain = (FirewallBlock*)malloc(sizeof(FirewallBlock));
      memset(chain, 0, sizeof(FirewallBlock));
      memcpy(chain, block, sizeof(FirewallBlock));

      printf("[ BLOC ] Added new block with hash %s...%s\n",
	     hash_string, hash_string + (SHA256_STRING_LENGTH - 10));
      save_blocks_to_file("chain.txt");
      return 0;
    }

  fw_chain = chain;
  while(fw_chain && fw_chain->next)
    {
      fw_chain = fw_chain->next;
    }

  fw_chain->next = (FirewallBlock*)malloc(sizeof(FirewallBlock));
  memset(fw_chain->next, 0, sizeof(FirewallBlock));
  memcpy(fw_chain->next, block, sizeof(FirewallBlock));
  printf("[ BLOC ] Added new block with hash %s...%s\n",
	 hash_string, hash_string + (SHA256_STRING_LENGTH - 10));

  save_blocks_to_file("chain.txt");
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

int load_blocks_from_file(const char *fname)
{
  FILE *file;
  FirewallBlock block;
  char buffer[256], temp_buf[6], *next_delim;
  int c;
  size_t pos;
   
  file = fopen(fname, "r");
  if(!file)
    {
      printf("[ BLOC ] No chain file found\n");
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
	  memset(&block, 0, sizeof(FirewallBlock));

	  /* Hash */
	  get_hash_from_string(block.last_hash, buffer, SHA256_DIGEST_LENGTH);
	  next_delim = strchr(buffer, ',');

	  /* Author */
	  memcpy(buffer, next_delim + 1, (buffer + 256) - next_delim - 1);
	  next_delim = strchr(buffer, ',');
	  memcpy(block.author, buffer, next_delim - buffer);

	  /* Source address */
	  memcpy(buffer, next_delim + 1, (buffer + 256) - next_delim - 1);
	  next_delim = strchr(buffer, ',');
	  memcpy(block.rule.source_addr, buffer, next_delim - buffer);

	  /* Source port */
	  memcpy(buffer, next_delim + 1, (buffer + 256) - next_delim - 1);
	  next_delim = strchr(buffer, ',');
	  memset(temp_buf, '\0', 6);
	  memcpy(temp_buf, buffer, next_delim - buffer);
	  block.rule.source_port = atoi(temp_buf);

	  /* Destination address */
	  memcpy(buffer, next_delim + 1, (buffer + 256) - next_delim - 1);
	  next_delim = strchr(buffer, ',');
	  memcpy(block.rule.dest_addr, buffer, next_delim - buffer); 

	  /* Destination port */
	  memcpy(buffer, next_delim + 1, (buffer + 256) - next_delim - 1);
	  next_delim = strchr(buffer, ',');
	  memset(temp_buf, '\0', 6);
	  memcpy(temp_buf, buffer, next_delim - buffer);
	  block.rule.dest_port = atoi(temp_buf);

	  memcpy(buffer, next_delim + 1, (buffer + 265) - next_delim - 1);
	  if(strcmp("ALLOW", buffer) == 0)
	    {
	      block.rule.action = ALLOW;
	    }
	  else if(strcmp("DENY", buffer) == 0)
	    {
	      block.rule.action = DENY;
	    }
	  else if(strcmp("BYPASS", buffer) == 0)
	    {
	      block.rule.action = BYPASS;
	    }
	  else if(strcmp("FORCE_ALLOW", buffer) == 0)
	    {
	      block.rule.action = FORCE_ALLOW;
	    }
	  else
	    {
	      block.rule.action = LOG;
	    }

	  add_block_to_chain(&block);
	  
	  memset(buffer, '\0', 256);
	  pos = 0;
	  continue;
	}
      buffer[pos++] = (char)c;
    }

  fclose(file);
  return 0;
}

int save_blocks_to_file(const char *fname)
{
  FILE *file;
  FirewallBlock *block;
  char hash_string[SHA256_STRING_LENGTH + 1];
  
  file = fopen(fname, "w+");
  if(!file)
    {
      printf("[ ERR  ] Could not create block file\n");
      return 1;
    }

  block = chain;
  if(block)
    {
      while(block && strlen(block->author) > 0)
	{
	  memset(hash_string, '\0', SHA256_STRING_LENGTH + 1);
	  get_hash_string(hash_string, block->last_hash,
			  SHA256_STRING_LENGTH + 1);
	  fwrite(hash_string, SHA256_STRING_LENGTH, 1, file);
	  fputc(',', file);
	  fwrite(block->author, strlen(block->author), 1, file);
	  fputc(',', file);
	  fwrite(block->rule.source_addr, strlen(block->rule.source_addr), 1,
		 file);
	  fputc(',', file);
	  fprintf(file, "%hd,", block->rule.source_port);
	  fwrite(block->rule.dest_addr, strlen(block->rule.dest_addr), 1,
		 file);
	  fputc(',', file);
	  fprintf(file, "%hd,", block->rule.dest_port);

	  switch(block->rule.action)
	    {
	    case ALLOW:
	      fputs("ALLOW", file);
	      break;
	    case DENY:
	      fputs("DENY", file);
	      break;
	    case BYPASS:
	      fputs("BYPASS", file);
	      break;
	    case FORCE_ALLOW:
	      fputs("FORCE_ALLOW", file);
	      break;
	    case LOG:
	      fputs("LOG", file);
	    }
	  
	  fputc('\n', file);
	  block = block->next;
	}
    }

  fclose(file);
  return 0;
}

int free_chain(void)
{
  FirewallBlock *block, *temp;
  block = chain;

  while(block)
    {
      temp = block;
      block = block->next;
      free(temp);
    }
  
  return 0;
}
