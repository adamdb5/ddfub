/**
 * @file net.h
 * @brief Network and protocol interface
 * @author Adam Bruce
 * @date 12 Feb 2021
 */

#ifndef NET_H
#define NET_H

#include "socket.h"

#ifdef _WIN32
#include <winsock2.h>
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
