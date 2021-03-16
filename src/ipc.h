/**
 * @file ipc.h
 * @brief Inter-process Communication interface
 * @author Adam Bruce
 * @date 4 Mar 2021
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

typedef enum { I_RULE, I_ENABLE, I_DISABLE, I_SHUTDOWN } IPCMessageType; 

typedef struct
{
  IPCMessageType message_type;
  FirewallRule rule;
} IPCMessage;

int init_ipc_server(void);
#ifdef _WIN32
int connect_ipc(void);
#endif
int init_ipc_client(void);
int cleanup_ipc(void);
int send_ipc_message(IPCMessage *message);
int recv_ipc_message(IPCMessage *message);

#endif
