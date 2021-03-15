/**
 * firewall.c
 * the implementations of all the fun firewall stuff!!
 */

#include "blockchain.h"
#include "firewall.h"
#include "ipc.h"
#include "net.h"

#include <string.h>

#include <openssl/sha.h>

static char local_address[INET_ADDRSTRLEN];

int recv_new_rule(FirewallRule *rule)
{
  IPCMessage msg;
  msg.message_type = RULE;
  memcpy(&msg.rule, rule, sizeof(FirewallRule));
  return send_ipc_message(&msg);
}

int send_new_rule(FirewallRule *rule)
{
  /* Send a new rule */

  /* - broadcast new rule
   * - collect acks
   * - wait a set timeout
   * - If acks > hosts / 2:
   *   - send rule to all hosts.
   *   - add to local chain
   * - Else
   *   - Do nothing
   */
  ConsensusMessage consensus_msg;
  RuleMessage rule_msg;
  FirewallBlock new_block;
  unsigned char block_hash[SHA256_DIGEST_LENGTH];

  get_local_address(local_address);
  /*get_block_hash(rule, */ 
  consensus_msg.type = CONSENSUS;
  consensus_msg.hops = 0;
  consensus_msg.consensus_type = C_BROADCAST;
  strncpy(consensus_msg.source_addr, local_address, INET_ADDRSTRLEN);
  send_to_all_consensus_message(&consensus_msg);
  

  return 0;
}
