/**
 * The big old firewall interface :)))
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
 * Valid firewall actions.
 */
typedef enum {ALLOW, BYPASS, DENY, FORCE_ALLOW, LOG} FirewallAction;

typedef struct
{
  char source_addr[INET_ADDRSTRLEN];
  uint16_t source_port;
  char dest_addr[INET_ADDRSTRLEN];
  uint16_t dest_port;
  FirewallAction action;
} FirewallRule;

int recv_new_rule(FirewallRule *rule);
int send_new_rule(FirewallRule *rule);

#endif
