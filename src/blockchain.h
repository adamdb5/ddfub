/**
 * @file blockchain.h
 * @brief Functions for creating and validating blockchains.
 * @author Adam Bruce
 * @date 03 Feb 2021
 */

#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include "firewall.h"

#include <openssl/sha.h>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

/**
 * @brief The length of SHA256 string representations.
 */ 
#define SHA256_STRING_LENGTH 64

/**
 * A block containing information for a firewall transaction.
 */
struct FirewallBlock
{
  unsigned char last_hash[SHA256_DIGEST_LENGTH]; /**< The hash of the previous block               */
  char author[INET_ADDRSTRLEN];         /**< The address of the block author              */
  FirewallRule rule;
  struct FirewallBlock *next;
};
typedef struct FirewallBlock FirewallBlock;

static FirewallBlock block;
static unsigned int ack_count;
static FirewallBlock *chain;

/**
 * @brief Calculates the SHA256 hash of a block.
 *
 * Calculates the SHA256 hash of a block, storing the digest in the given
 * buffer. This buffer should have a size of SHA256_DIGEST_LENGTH.
 * @param buffer the buffer to store the digest in.
 * @param block a pointer to the block to hash.
 * @param buffer_size the size of the buffer to store the hash in.
 * @return whether the hash has been calculated successfully. If any parameters
 * are invalid, the return value will be 1, otherwise the return value will be
 * 0. 
 */
int get_block_hash(unsigned char* buffer, FirewallBlock* block, int buffer_size);

/**
 * @brief Formats a SHA256 digest into human-readable string.
 *
 * Formats a SHA256 digest into a human-readable string, storing the result into
 * the given buffer. This buffer should have a size of SHA256_STRING_LENGTH.
 * @param buffer the buffer to store the string in.
 * @param hash the hash digest to format into a string.
 * @param buffer_size the size of the buffer to store the string in.
 * @return whether the string has been formatted succesfully. If any parameters
 * are invalid, the return value will be 1, otherwise the return value will be
 * 0.
 */
int get_hash_string(char* buffer, unsigned char* hash, int buffer_size);

int add_block_to_chain(FirewallBlock *block);

int rotate_pending_rules(void);
int add_pending_rule(char *addr);
int is_pending(char *addr);
int remove_pending_rule(char *addr);
int get_last_hash(char *buffer);
#endif
