/**
 * @file net.h
 * @brief Network and protocol interface.
 * @author Adam Bruce
 * @date 22 Mar 2021
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

/**
 * @brief The maximum number of hops before a message is destroyed.
 */
#define MAX_CONSENSUS_HOPS 5

/**
 * @brief All available message types for network transactions.
 */
typedef enum
  {
    ADVERTISEMENT,  /**< Host advertisement message             */
    CONSENSUS,      /**< Firewall transaction consensus message */
    RULE            /**< Firewall transaction rule message      */ 
  } MessageType;

/**
 * @brief All available message subtypes for network transactions.
 */
typedef enum
  {
    BROADCAST,      /**< Broadcast message       */
    ACK             /**< Acknowledgement message */
  } MessageSubType;

/**
 * @brief The structure to store all known hosts as a linked list.
 */
struct HostList
{
  struct HostList *next;       /**< The next host in the list */
  char addr[INET_ADDRSTRLEN];  /**< The host's address        */
};
typedef struct HostList HostList; 

/**
 * @brief The structure to store an advertisement message.
 */
typedef struct
{
  MessageType type;                  /**< The message type (ADVERTISEMENT)  */
  uint8_t hops;                      /**< The hop count                     */
  MessageSubType advertisement_type; /**< The message subtype               */
  char source_addr[INET_ADDRSTRLEN]; /**< The source address of the message */
  char target_addr[INET_ADDRSTRLEN]; /**< The target address of the message */
  char next_addr[INET_ADDRSTRLEN];   /**< The next address of the message   */
} AdvertisementMessage;

/**
 * @brief The structure to store a consensus message.
 */
typedef struct
{
  MessageType type;                  /**< The message type (CONSENSUS)      */
  uint8_t hops;                      /**< The hop count                     */
  MessageSubType consensus_type;     /**< The message subtype               */
  char source_addr[INET_ADDRSTRLEN]; /**< The source address of the message */
  char target_addr[INET_ADDRSTRLEN]; /**< The target address of the message */
  char next_addr[INET_ADDRSTRLEN];   /**< The next address of the message   */
  unsigned char last_block_hash[SHA256_DIGEST_LENGTH]; /**< The hash of the 
							    last block      */
} ConsensusMessage;

/**
 * @brief The structure of a firewall rule message.
 */
typedef struct
{
  MessageType type;                  /**< The message type (RULE)           */
  uint8_t hops;                      /**< The hop count                     */
  MessageSubType rule_type;          /**< The message subtype               */
  char source_addr[INET_ADDRSTRLEN]; /**< The source address of the message */
  char target_addr[INET_ADDRSTRLEN]; /**< The target address of the message */
  char next_addr[INET_ADDRSTRLEN];   /**< The next address of the message   */
  FirewallRule rule;                 /**< The firewall rule                 */
} RuleMessage;

/**
 * @brief Retrieves the local address of the host's Ethernet adapter.
 *
 * Retrieves the local address of the host's Ethernet adapter using the network
 * API of the OS.
 * @param buffer the buffer to copy the address into.
 * @return whether the address was succesfully obtained. If an error has
 * occurred, the return value will be 1, otherwise the return value will be 0.
 */ 
int get_local_address(char* buffer);

/**
 * @brief Loads a list of hosts from a file.
 *
 * Loads a list of hosts from the given file into the HostList struct.
 * @param fname the name of the file containing the hosts.
 * @return whether the list of hosts was successfully loaded. If an error has
 * occurred, the return value will be 1, otherwise the return value will be 0.
 */
int load_hosts_from_file(const char* fname);

/**
 * @brief Adds a host to the host list.
 *
 * Appends the given host to the list of hosts.
 * @param addr the address of the new host.
 * @return whether the host was appended successfully. If an error has occurred
 * the return value will be 1, otherwise the return value will be 0.
 */
int add_host(char* addr);

/**
* @brief Checks if a given host exists in the host list.
*
* Searches the list of hosts for the given address.
* @param addr the address to search for.
* @return whether the host was found. If the host was found, the return value
* will be 1, otherwise the return value will be 0.
*/
int check_host_exists(char *addr);

/**
 * @brief Returns the number of remote hosts known by the local host.
 *
 * Counts how many hosts are known locally.
 * @return the number of hosts.
 */
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

/**
 * @brief Sends an advertisement message.
 *
 * Sends an advertisement to a remote host using the address information within
 * the message.
 * @param message the message to send.
 * @return the number of bytes sent. If an error has occurred, the return value
 * will be negative.
 */
int send_advertisement_message(AdvertisementMessage *message);

/**
 * @brief Sends an advertisement message to all known hosts.
 *
 * Sends an advertisement message to all known hosts. The address within the
 * given message will be modified.
 * @param message the message to send.
 * @return whether all messages were sent successfully. If an error has
 * occurred, the return value will be 1, otherwise the return value will be 0.
 */
int send_to_all_advertisement_message(AdvertisementMessage *message);

/**
 * @brief Parses a received raw advertisement message.
 *
 * Parses raw memory into an instance of an AdvertisementMessage. Upon
 * identifying the message subtype, either recv_advertisement_broadcast or
 * recv_advertisement_ack is called.
 * @param buffer the raw memory of the message.
 * @return whether the advertisement message was parsed successfully. If an 
 * error has occurred, the return value will be 1, otherwise the return value 
 * will be 0.
 */
int recv_advertisement_message(void *buffer);

/**
 * @brief Handles advertisement broadcasts.
 *
 * Handles advertisement broadcast messages. If the host is not known, then they
 * are appended to the host list. Additionally, if the hop count has not
 * exceeded the hop limit, it is forwarded to all known hosts.
 * @param message the received message.
 * @return whether the message was handled correctly. If an error has occurred,
 * the return value will be 1, otherwise the return value will be 0.
 */
int recv_advertisement_broadcast(AdvertisementMessage* message);

/**
 * @brief Handles advertisement acknowledgements.
 *
 * Handles advertisement acknowledgement messages. Upon receiving an ack, if the
 * host is not known, then thay are appended to the host list.
 * @param message the received message.
 * @return whether the message was handled correctly. If an error has occurred,
 * the return value will be 1, otherwise the return value will be 0.
 */
int recv_advertisement_ack(AdvertisementMessage* message);

/**
 * @brief Sends a consensus message.
 *
 * Sends a consensus message to a remote host using the address information
 * within the message.
 * @param message the message to send.
 * @return the number of bytes sent. If an error has occurred, the return value
 * will be negative.
 */
int send_consensus_message(ConsensusMessage *message);

/**
 * @brief Sends a consensus message to all known hosts.
 *
 * Sends a consensus message to all known hosts. The address within the given
 * message will be modified.
 * @param message the message to send.
 * @return whether all messages were sent successfully. If an error has
 * occurred, the return value will be 1, otherwise the return value will be 0.
 */
int send_to_all_consensus_message(ConsensusMessage *message);

/**
 * @brief Parses a received raw consensus message.
 *
 * Parses raw memory into an instance of an ConsensusMessage. Upon
 * identifying the message subtype, either recv_consensus_broadcast or
 * recv_consensus_ack is called.
 * @param buffer the raw memory of the message.
 * @return whether the consensus message was parsed successfully. If an error
 * has occurred, the return value will be 1, otherwise the return value will be
 * 0.
 */
int recv_consensus_message(void *buffer);

/**
 * @brief Handles consensus broadcasts.
 *
 * Handles consensus broadcast messages. If the host is known, and the consensus
 * hash matches the host's last hash, then an ack is sent. Additionally, if the
 * hop count has not exceeded the hop limit, the broadcast is forwarded to all
 * known hosts.
 * @param message the received message.
 * @return whether the message was handled correctly. If an error has occurred,
 * the return value will be 1, otherwise the return value will be 0.
 */
int recv_consensus_broadcast(ConsensusMessage *message);

/**
 * @brief Handles consensus acknowledgements.
 *
 * Handles consensus acknowledgement messages. Upon receiving an ack, the
 * ack_count is incremented.
 * @param message the received message.
 * @return whether the message was handled correctly. If an error has occurred,
 * the return value will be 1, otherwise the return value will be 0.
 */
int recv_consensus_ack(ConsensusMessage *message);

/**
 * @brief Sends a firewall rule message.
 *
 * Sends a firewall rule message to a remote host using the address information
 * within the message.
 * @param message the message to send.
 * @return the number of bytes sent. If an error has occurred, the return value
 * will be negative.
 */
int send_rule_message(RuleMessage *message);

/**
 * @brief Sends a firewall rule message to all known hosts.
 *
 * Sends a firewall rule message to all known hosts. The address within the 
 * given message will be modified.
 * @param message the message to send.
 * @return whether all messages were sent successfully. If an error has
 * occurred, the return value will be 1, otherwise the return value will be 0.
 */
int send_to_all_rule_message(RuleMessage *message);

/**
 * @brief Parses a received raw firewall rule message.
 *
 * Parses raw memory into an instance of an RuleMessage. Upon identifying the 
 * message subtype, recv_rule_broadcast is called.
 * @param buffer the raw memory of the message.
 * @return whether the firewall rule message was parsed successfully. If an 
 * error has occurred, the return value will be 1, otherwise the return value 
 * will be 0.
 */
int recv_rule_message(void *buffer);

/**
 * @brief Handles firewall rule broadcasts.
 *
 * Handles firewall rule messages. If the host is known, and the host has sent a
 * consensus ack, then the firewall rule is accepted and appended to the chain.
 * @param message the received message.
 * @return whether the message was handled correctly. If an error has occurred,
 * the return value will be 1, otherwise the return value will be 0.
 */
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
