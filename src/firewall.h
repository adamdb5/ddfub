/**
 * @file firewall.h
 * @brief High level functions for handling firewall interactions.
 * @author Adam Bruce
 * @date 22 Mar 2021
 */

#ifndef FIREWALL_H
#define FIREWALL_H

#ifdef _WIN32
#include <ws2tcpip.h>
#include <stdint.h>
typedef uint16_t u_int16_t;
#else
#include <arpa/inet.h>
#endif

/**
 * @brief All valid firewall rule actions.
 */
typedef enum
  {
    ALLOW,          /**< The connection should be allowed            */ 
    BYPASS,         /**< The connection should be bypassed           */
    DENY,           /**< The connection should be denied             */
    FORCE_ALLOW,    /**< The connection shoule be forcefully allowed */
    LOG             /**< The connection should be logged             */
  } FirewallAction;

/**
 * @brief The structure of a firewall rule.
 */
typedef struct
{
  char source_addr[INET_ADDRSTRLEN]; /**< The rule's source address      */
  uint16_t source_port;              /**< The rule's source port         */
  char dest_addr[INET_ADDRSTRLEN];   /**< The rule's destination address */
  uint16_t dest_port;                /**< The rule's destination port    */
  FirewallAction action;             /**< The rule's action              */
} FirewallRule;

/**
 * @brief The function called once a new firewall rule is available.
 *
 * This function is called once a firewall rule has been submitted by remote
 * host, and the network has given consenus to the new firewall rule.
 * @param rule the new firewall rule that was received.
 * @return whether the corresponding IPC message to the OS was sent
 * successfully. If an error has occurred, the return value will be 1, otherwise
 * the return value will be 0.
 */
int recv_new_rule(FirewallRule *rule);

/**
 * @brief The function used to send a new firewall rule.
 *
 * This function is called when a firewall rule is sent from the OS via IPC.
 * The function will first attempt to gain consensus within the network, and if
 * successfull, it will transmit the new rule to all known hosts.
 * @param rule the new firewall to send.
 * @return whether the firewall rule was sent. If an error has occurred, the
 * return value will be 1, otherwise the return value will be 0.
 */
int send_new_rule(FirewallRule *rule);

#endif
