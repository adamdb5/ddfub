/**
 * firewall.c
 * the implementations of all the fun firewall stuff!!
 */

#include "blockchain.h"
#include "firewall.h"
#include "ipc.h"
#include "net.h"

#include <string.h>
#include <stdio.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#include <openssl/sha.h>

#define TIMEOUT 500

static char local_address[INET_ADDRSTRLEN];

int recv_new_rule(FirewallRule *rule)
{
  IPCMessage msg;
  msg.message_type = I_RULE;
  memcpy(&msg.rule, rule, sizeof(FirewallRule));
  return send_ipc_message(&msg);
}

int send_new_rule(FirewallRule *rule)
{
  ConsensusMessage consensus_msg;
  RuleMessage rule_msg;
  FirewallBlock block;
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
  get_local_address(local_address);
  consensus_msg.type = CONSENSUS;
  consensus_msg.hops = 0;
  consensus_msg.consensus_type = C_BROADCAST;
  strncpy(consensus_msg.source_addr, local_address, INET_ADDRSTRLEN);
  get_last_hash(consensus_msg.last_block_hash);
  send_to_all_consensus_message(&consensus_msg);

  /* wait timeout */
#ifdef _WIN32
  Sleep(TIMEOUT);
#else
  usleep(TIMEOUT * 1000);
#endif
  
  /* at least half known hosts have have consensus */
  if(ack_count < (get_host_count() / 2))
    {
      printf("[INFO] Consensus not achieved.\n");
      ack_count = 0;
      return 1;
    }

  rule_msg.type = RULE;
  rule_msg.hops = 0;
  rule_msg.rule_type = R_BROADCAST;
  strncpy(rule_msg.source_addr, local_address, INET_ADDRSTRLEN);
  memcpy(&rule_msg.rule, rule, sizeof(FirewallRule));
  send_to_all_rule_message(&rule_msg);

  get_last_hash(block.last_hash);
  strncpy(block.author, local_address, INET_ADDRSTRLEN);
  memcpy(&block.rule, rule, sizeof(FirewallRule));
  add_block_to_chain(&block);

  return 0;
}
