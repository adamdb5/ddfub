/**
 * @file blockchain.h
 * @brief Functions for creating and validating blockchains.
 * @author Adam Bruce
 * @date 22 Mar 2021
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
  unsigned char last_hash[SHA256_DIGEST_LENGTH]; /**< The hash of the previous block              */
  char author[INET_ADDRSTRLEN];                  /**< The address of the block author             */
  FirewallRule rule;                             /**< The firewall rule associated with the block */
  struct FirewallBlock *next;
};
typedef struct FirewallBlock FirewallBlock;

/**
 * The firewall block used to store this host's proposed new rule.
 */
static FirewallBlock block;

/**
 * The number of acknowledgements this host has received for a proposed rule.
 */
static unsigned int ack_count;

/**
 * The blockchain of current firewall rules.
 */
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
int get_block_hash(unsigned char *buffer, FirewallBlock *block, int buffer_size);

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
int get_hash_string(char *buffer, unsigned char *hash, int buffer_size);

/**
 * @brief Adds a new firewall block onto the chain.
 * 
 * Appends the new firewall block to the linked list of firewall block.
 * @param block the new block to add to the chain.
 * @return whether the block has been added to the chain. If an the block is
 * is null or the block's memory could not be allocated, the return value
 * will be 1, otherwise the return value will be 0.
 */
int add_block_to_chain(FirewallBlock *block);

/**
 * @brief Rotates the pending firewall rules.
 *
 * Rotates this host's list of pending firewall rules, such that the oldest rule
 * is removed from the list, allowing a new block to be added.
 * @return whether the list was rotated. If an error has occurred, the return
 * value will be 1, otherwise the return value will be 0.
 */
int rotate_pending_rules(void);

/**
 * @brief Adds a new rule to the list of pending rules.
 *
 * Appends a new rule to the list of pending rules, this involves rotating the
 * list, and adding the new rule's author.
 * @param addr the author of the new pending rule.
 * @return whether the rule was added. If an error has occurred, the return
 * value will be 1, otherwise the return value will be 0.
 */ 
int add_pending_rule(char *addr);

/**
 * @brief Checks if the given address has a pending rule.
 *
 * Searches the pending rule list for the given address. If the address is found
 * then the host has a pending rule.
 * @param addr the author to check for pending rules.
 * @return whether any pending rules for the author were found. If a pending rule
 * is found, the return value will be 1, otherwise the return value will be 0.
 */
int is_pending(char *addr);

/**
 * @brief Removes a pending rule from the list.
 *
 * Searches for a pending rule with the given address. If a matching rule is
 * found, the rule is removed.
 * @param addr the address to remove.
 * @return whether the pending rule was removed. If an error has occurred, the
 * return value will be 1, otherwise the return value will be 0.
 */
int remove_pending_rule(char *addr);

/**
 * @brief Returns the hash of the last firewall block in the chain.
 *
 * Gets the SHA256 hash of the last firewall block in the chain. If the chain
 * is empty, the buffer will be empty.
 * @param buffer the buffer that the hash value will be copied into. This buffer
 * should be at least SHA256_DIGEST_LENGTH bytes in size.
 * @return whether the hash value was copied successfully, If an error has
 * occurred, the return value will be 1, otherwuse the return value will be 0.
 */
int get_last_hash(unsigned char *buffer);
#endif
