/**
 * @file socket.h
 * @brief Cross-platform socket interface.
 * @author Adam Bruce
 * @date 15 Dec 2020
 */

#ifndef SOCKET_H_
#define SOCKET_H_

#ifdef _WIN32
	#ifndef _WIN32_WINNT
		#define _WIN32_WINNT 0x0501  /* Patch for older NT kernels */
	#endif
	
	#include <winsock2.h>
#else
	#include <sys/socket.h>
	#include <netinet/in.h>
#endif


#ifdef _WIN32
	/**
	 * @brief Cross platform socket type.
	 */
	typedef SOCKET socket_t;
#else
	/**
	 * @brief Cross platform socket type.
	 */
	typedef int socket_t;
	
	/** 
	 * @brief
	 * UNIX equivalent to WinSocks's INVALID_SOCKET constant
	 * */
	#define INVALID_SOCKET -1 
#endif


/**
 * @brief Initialises the socket API.
 * 
 * Initialises the relevent socket APIs for each operating system.
 * For the NT kernel, this involves initialising Winsock. For UNIX systems, this
 * function does nothing.
 * @return the status of the socket API. If an error has occurred, a non-zero
 * value will be returned, otherwise the return value will be 0.
 */
int init_sockets(void);

/**
 * @brief Uninitialises the socket API.
 * 
 * Uninitialises the relevent socket APIs for each operating system.
 * For the NT kernel, this involves uninitialising Winsock. For UNIX systems, 
 * this function does nothing.
 * @return whether the API was succesfully cleaned up. If an error has occurred, 
 * a non-zero value will be returned, otherwise the return value will be 0.
 */
int cleanup_sockets(void);

/**
 * @brief Creates a new socket.
 * 
 * Creates a UDP socket using the relevant API for the operating system.
 * @return a new socket descriptor, or 0 if a socket could not be created.
 */
socket_t create_socket(void);

/**
 * @brief Closes a socket.
 * 
 * Closes the socket using the relevant API for the operating system.
 * @param sock the socket to close.
 */
void close_socket(socket_t sock);

/**
 * @brief Binds a socket to a port.
 * 
 * Binds the socket to a port, and configures it to use IP and UDP.
 * @param sock the socket to bind.
 * @param port the port to bind the socket to. 
 * @return whether the socket was successfully binded. If an error has occurred,
 * the return value will be -1, otherwise the return value will be 0.
 */
int bind_socket(socket_t sock, int port);

/**
 * @brief Sends a message to a remote socket.
 * 
 * Sends the data stored within the buffer to a remote socket.
 * @param sock the local socket.
 * @param message the data to send.
 * @param length the length of the data.
 * @param flags the flags used to configure the sendto operation.
 * @param dest_addr the destination address
 * @return how many bytes were successfully sent.
 */
int send_to_socket(socket_t sock, void* message, size_t length, int flags,
                   struct sockaddr_in dest_addr);
                 
/**
 * @brief Receives a message from a socket.
 * 
 * Receives a message from a socket.
 * @param sock the socket.
 * @param buffer the buffer to read the message into.
 * @param length the number of bytes to read.
 * @param flags the flags used to configure the recv operation.
 * @return how many bytes were successfully read.
 */  
int recv_from_socket(socket_t sock, void* buffer, size_t length, int flags);

#endif
