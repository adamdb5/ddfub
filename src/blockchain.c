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
