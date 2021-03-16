/**
 * @file net.h
 * @brief Network and protocol interface
 * @author Adam Bruce
 * @date 12 Feb 2021
 */

#ifndef NET_H
#define NET_H

#include "socket.h"
#include "firewall.h"

#include <openssl/sha.h>

#ifdef _WIN32
#include <inttypes.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netdb.h>
#endif

/**
 * @brief Port for receiving messages
 */
#define PORT_RECV 8070

/**
 * @brief Port for sending messages
 */ 
#define PORT_SEND 8071

/**
 * @brief The maximum number of network advertisement hops. 
 */
#define MAX_ADVERTISEMENT_HOPS 5

#define MAX_CONSENSUS_HOPS 5

/**
 * ADVERTISE: Advertise a new device.
 * CONSENSUS: Consensus related actions.
 * FIREWALL:  Send / receive firewall queries.
 */
typedef enum { ADVERTISEMENT, CONSENSUS, RULE } MessageType;
typedef enum { BROADCAST, ACK } AdvertisementType;
typedef enum { C_BROADCAST, C_ACK } ConsensusType;
typedef enum { R_BROADCAST } RuleType;

struct HostList
{
  struct HostList *next;
  char addr[INET_ADDRSTRLEN];
};
typedef struct HostList HostList; 

typedef struct
{
  MessageType type;
  uint8_t hops;
  AdvertisementType advertisement_type;
  char source_addr[INET_ADDRSTRLEN];
  char target_addr[INET_ADDRSTRLEN];
  char next_addr[INET_ADDRSTRLEN];
} AdvertisementMessage;

typedef struct
{
  MessageType type;
  uint8_t hops;
  ConsensusType consensus_type;
  char source_addr[INET_ADDRSTRLEN];
  char target_addr[INET_ADDRSTRLEN];
  char next_addr[INET_ADDRSTRLEN];
  unsigned char last_block_hash[SHA256_DIGEST_LENGTH];
} ConsensusMessage;

typedef struct
{
  MessageType type;
  uint8_t hops;
  RuleType rule_type;
  char source_addr[INET_ADDRSTRLEN];
  char target_addr[INET_ADDRSTRLEN];
  char next_addr[INET_ADDRSTRLEN];
  FirewallRule rule;
} RuleMessage;

int get_local_address(char* buffer);
int load_hosts_from_file(const char* fname);
int add_host(char* addr);
int print_hosts(void);
int check_host_exists(char *addr);
int get_host_count(void);

/**
 * @brief Initialises the network API.
 *
 * Initialises the network API by initialising the underlying socket API and
 * creating the necessary sockets for sending and receiving messages.
 * @return the status of the network API. If an error has occurred, a non-zero
 * value will be returned, otherwise the return value will be 0.
 */
int init_net(void);

/**
 * @brief Uninitialises the network API.
 *
 * Uninitialises the network API by closing the underlying sockets and cleaning
 * up the relevant socket API.
 * @return whether the network API was successfully cleaned up. If an error has
 * occurred, a non-zero value will be returned, otherwise the return value will
 * be 0.
 */
int cleanup_net(void);

/**
 * @brief Sends a message to a remote host.
 *
 * Sends a message to the remote host specified by their IP address.
 * @param ip_address the remote host's IP address.
 * @param message the message / data to send to the remote host.
 * @param length the length of the message / data.
 * @return the number of bytes sent to the remote host. If an error has
 * occurred, a negative value will be returned.
 */
int send_to_host(char* ip_address, void* message, size_t length);

int send_advertisement_message(AdvertisementMessage *message);
int send_to_all_advertisement_message(AdvertisementMessage *message);
int recv_advertisement_message(void *buffer);
int recv_advertisement_broadcast(AdvertisementMessage* message);
int recv_advertisement_ack(AdvertisementMessage* message);

int send_consensus_message(ConsensusMessage *message);
int send_to_all_consensus_message(ConsensusMessage *message);
int recv_consensus_message(void *buffer);
int recv_consensus_broadcast(ConsensusMessage *message);
int recv_consensus_ack(ConsensusMessage *message);

int send_rule_message(RuleMessage *message);
int send_to_all_rule_message(RuleMessage *message);
int recv_rule_message(void *buffer);
int recv_rule_broadcast(RuleMessage *message);

/**
 * @brief Waits for a message to be received.
 * 
 * Waits for a message to be recieved. Once received, <length> bytes will be
 * copied into the given buffer.
 * @param buffer the buffer to copy the message into.
 * @param length the number of bytes to read.
 * @return the number of bytes received. If an error has occurred, a negative
 * value will be returned.
 */
int poll_message(void* buffer, size_t length);

#endif
