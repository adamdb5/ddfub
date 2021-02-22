/**
 * @file blockchain.h
 * @brief Functions for creating and validating blockchains.
 * @author Adam Bruce
 * @date 03 Feb 2021
 */

#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

/**
 * @brief The length of SHA256 string representations.
 */ 
#define SHA256_STRING_LENGTH 64

/**
 * Valid firewall actions.
 */
typedef enum {ALLOW, BYPASS, DENY, FORCE_ALLOW, LOG} FirewallAction;

/**
 * A block containing information for a firewall transaction.
 */
typedef struct
{
  char last_hash[256];   /**< The hash of the previous block               */
  int  nonce;            /**< Random nonce                                 */
  char author[100];      /**< The IP of the block author                   */
  
  char source_addr[15];  /**< The source address of the firewall rule      */
  int  source_port;      /**< The source port of the firewall rule         */
  char dest_addr[15];    /**< The destination address of the firewall rule */
  int dest_port;         /**< The destination port of the firewall rule    */
  FirewallAction action; /**< The action associated with the firewall rule */
} FirewallBlock;

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
#endif
