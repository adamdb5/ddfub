/**
 * @file firewall.c
 * @brief High level functions for handling firewall interactions.
 * @author Adam Bruce
 * @date 22 Mar 2021
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

#define TIMEOUT 5000 /* remove last 0 */

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

  get_local_address(local_address);
  consensus_msg.type = CONSENSUS;
  consensus_msg.hops = 0;
  consensus_msg.consensus_type = BROADCAST;
  strncpy(consensus_msg.source_addr, local_address, INET_ADDRSTRLEN);
  strncpy(consensus_msg.target_addr, local_address, INET_ADDRSTRLEN);
  get_last_hash(consensus_msg.last_block_hash);
  send_to_all_consensus_message(&consensus_msg);
  printf("[ CONS ] Sent consensus message to %d known host(s)\n",
	 get_host_count());

#ifdef _WIN32
  Sleep(TIMEOUT);
#else
  usleep(TIMEOUT * 1000);
#endif

  /* at least half known hosts have consensus */
  if(get_acks() < (get_host_count() + 1) / 2)
    {
      printf("[ CONS ] Consensus not achieved (%d/%d hosts)\n", get_acks(),
	     get_host_count());
      reset_acks();
      return 1;
    }

  printf("[ CONS ] Consensus achieved (%d/%d hosts)\n", get_acks(),
	 (get_host_count() + 1) / 2);
  reset_acks();

  rule_msg.type = RULE;
  rule_msg.hops = 0;
  rule_msg.rule_type = BROADCAST;
  strncpy(rule_msg.source_addr, local_address, INET_ADDRSTRLEN);
  strncpy(rule_msg.target_addr, local_address, INET_ADDRSTRLEN);
  memcpy(&rule_msg.rule, rule, sizeof(FirewallRule));
  send_to_all_rule_message(&rule_msg);
  printf("[ RULE ] Sent new rule message to %d known hosts(s)\n",
	 get_host_count());

  memset(&block, 0, sizeof(FirewallBlock));
  get_last_hash(block.last_hash);
  strncpy(block.author, local_address, INET_ADDRSTRLEN);
  memcpy(&block.rule, rule, sizeof(FirewallRule));
  add_block_to_chain(&block);
  
  return 0;
}
