/**
 * @file blockchain_test.c
 * @brief Tests for the functions in blockchain.c.
 * @author Adam Bruce
 * @date 03 Feb 2021
 */

#include "../blockchain.h"

#include <openssl/sha.h>

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

/** 
 * Tests if get_block_hash returns a non-zero integer if the
 * pointer to buffer is NULL.
 */
void get_block_hash_null_buffer(void **state)
{
  unsigned char* hash;
  FirewallBlock block;
  int result;

  hash = NULL;
  result = get_block_hash(hash, &block, 65);
  assert_int_equal(result, 1);
}

/** 
 * Tests if get_block_hash returns a non-zero integer if the
 * provided buffer is smaller than the hash digest length.
 */
void get_block_hash_buffer_too_small(void **state)
{
  unsigned char hash[30];
  FirewallBlock block;
  int result;

  result = get_block_hash(hash, &block, 30);
  assert_int_equal(result, 1);
}

/**
 * Tests if get_block_hash returns a non-zero integer if the
 * pointer to block is NULL.
 */ 
void get_block_hash_null_block(void **state)
{
  unsigned char hash[SHA256_DIGEST_LENGTH];
  FirewallBlock *block;
  int result;
  
  block = NULL;
  result = get_block_hash(hash, block, 32);
}

/**
 * Tests if get_block_hash returns the correct hash digest for
 * a valid block.
 */
void get_block_hash_valid(void **state)
{
  unsigned char hash[SHA256_DIGEST_LENGTH];
  FirewallBlock block;
  unsigned char expected_memory[SHA256_DIGEST_LENGTH];

  memset(&block, 0, sizeof(FirewallBlock));
  strcpy(block.author, "name");
  strcpy(block.last_hash, "last hash");
  memcpy((void*)expected_memory, 
	 "\xc1\xa4\x81\xde\xb4\x45\x1b\x35\x76\x62"  \
	 "\xa2\xdf\x4c\x12\xa2\x2b\x97\xf1\x50\xf5"  \
	 "\xe3\xb2\xe3\x5e\x16\x9a\x0d\x1b\xcc\x51\x54\x92",
	 SHA256_DIGEST_LENGTH);
	 

  get_block_hash(hash, &block, SHA256_DIGEST_LENGTH);
  assert_memory_equal(hash, expected_memory, SHA256_DIGEST_LENGTH);
}

/**
 * Tests if get_hash_string returns a non-zero integer if the
 * pointer to hash is NULL.
 */
void get_hash_string_null_hash(void **state)
{
  unsigned char *hash;
  char hash_string[SHA256_STRING_LENGTH + 1];
  int result;
  
  hash = NULL;
  result = get_hash_string(hash_string, hash, SHA256_STRING_LENGTH + 1);
  assert_int_equal(result, 1); 
}

/**
 * Tests if get_hash_string returns a non-zero integer if the
 * buffer is smaller than the hash string.
 */ 
void get_hash_string_buffer_too_small(void **state)
{
  unsigned char hash[SHA256_DIGEST_LENGTH];
  char hash_string[20];
  int result;

  memcpy((void*)hash, 
	 "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a" \
	 "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a" \
	 "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c",
	 SHA256_DIGEST_LENGTH);
	 

  result = get_hash_string(hash_string, hash, 20);
  assert_int_equal(result, 1);

}

/**
 * Tests if get_hash_string returns a non-zero integer if the
 * pointer to buffer is NULL.
 */
void get_hash_string_null_buffer(void **state)
{
  unsigned char hash[SHA256_DIGEST_LENGTH];
  char *hash_string;
  int result;

  memcpy((void*)hash, 
	 "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a" \
	 "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a" \
	 "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c",
	 SHA256_DIGEST_LENGTH);
  hash_string = NULL;
  
  result = get_hash_string(hash_string, hash, SHA256_STRING_LENGTH);
  assert_int_equal(result, 1);
}

/** 
 * Tests if get__hash_string returns the correct hash for a
 * valid digest.
 */
void get_hash_string_valid(void **state)
{
  unsigned char hash[SHA256_DIGEST_LENGTH];
  char hash_string[SHA256_STRING_LENGTH + 1];

  memcpy((void*)hash, 
	  "\xc1\xa4\x81\xde\xb4\x45\x1b\x35\x76\x62" \
	  "\xa2\xdf\x4c\x12\xa2\x2b\x97\xf1\x50\xf5" \
	  "\xe3\xb2\xe3\x5e\x16\x9a\x0d\x1b\xcc\x51\x54\x92",
	  SHA256_DIGEST_LENGTH);
  
  get_hash_string(hash_string, hash, SHA256_STRING_LENGTH + 1);
  assert_string_equal(hash_string,
      "c1a481deb4451b357662a2df4c12a22b97f150f5e3b2e35e169a0d1bcc515492");
}

int main(void)
{
  const struct CMUnitTest tests[] =
    {
      cmocka_unit_test(get_block_hash_null_buffer),
      cmocka_unit_test(get_block_hash_buffer_too_small),
      cmocka_unit_test(get_block_hash_null_block),
      cmocka_unit_test(get_block_hash_valid),
      cmocka_unit_test(get_hash_string_null_buffer),
      cmocka_unit_test(get_hash_string_buffer_too_small),
      cmocka_unit_test(get_hash_string_null_hash),
      cmocka_unit_test(get_hash_string_valid),
    };

  cmocka_run_group_tests(tests, NULL, NULL);
  return 0;
}
