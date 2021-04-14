/**
 * @file ipc.h
 * @brief Inter-process Communication interface.
 * @author Adam Bruce
 * @date 22 Mar 2021
 */

#include "firewall.h"

#ifndef IPC_H
#define IPC_H

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#endif

/**
 * @brief All valid IPC message types.
 */
typedef enum
  {
    I_RULE,         /**< New rule                      */
    I_ENABLE,       /**< Enable network communication  */
    I_DISABLE,      /**< Disable network communication */
    I_SHUTDOWN,     /**< Shutdown the framework        */
    O_RULE          /**< New rule from another node    */
  } IPCMessageType; 

/**
 * @brief The structure of a IPC message.
 */
typedef struct
{
  IPCMessageType message_type; /**< The IPC message type */
  FirewallRule rule;           /**< The firewall rule (if type is I_RULE) */
} IPCMessage;

/**
 * @brief Initialise the IPC in server mode.
 *
 * Initialises the underlying IPC mechanism, and creates a new connection. If
 * on *nix this is achieved using the POSIX message queue, or Named Pipes if
 * on windows.
 * @return whether the IPC was successfully initialised, and a connection
 * esatblished. If an error has occurred, the return value will be 1, otherwise
 * the return value will be 0.
 */
int init_ipc_server(void);

#ifdef _WIN32
/**
 * @brief Connects to the relevant Named Pipe (Windows Only).
 *
 * Establishes a connection to the previously created Named Pipe on the Windows
 * operating system.
 * @return whether the connection to the Named Pipe was succesful. If an error
 * has occurred, the return value will be 1, otherwise the return value will be
 * 0.
 */
int connect_ipc(void);
#endif

/**
 * @brief Initialise the IPC in client mode.
 *
 * Connects to a previously established IPC server.
 * @return whether the connection was succesfully established. If an error has
 * occurred the return value will be 1, otherwise the return value will be 0.
 */
int init_ipc_client(void);

/**
 * @brief Cleans up the IPC session.
 *
 * Terminates the connection to the IPC session, and tears down the underlying
 * session.
 * @return whether the connection was successfully terminated. If an error has
 * occurred, the return value will be 1, otherwise the return value will be 0.
 */
int cleanup_ipc(void);

/**
 * @brief Send and IPC message to a client application.
 *
 * Sends an IPC message to a client connected via IPC.
 * @param message the message to send.
 * @return whether the message was sent successfully. If an error has occurred,
 * the return value will be 1, otherwise the return value will be 0.
 */
int send_ipc_message(IPCMessage *message);

/**
 * @brief Retrieves an IPC message.
 *
 * Checks for an IPC message waiting in the queue. If a message is found, it is
 * copied into the message parameter.
 * @param message the message that a waiting message will be copied into.
 * @return whether an IPC message has been copied from the queue. If an error
 * has occurred, the return value will be 1, otherwise the return value will be
 * 0.
 */
int recv_ipc_message(IPCMessage *message);

#endif
