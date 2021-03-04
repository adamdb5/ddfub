/**
 * @file ipc.h
 * @brief Inter-process Communication interface
 * @author Adam Bruce
 * @date 4 Mar 2021
 */

#ifndef IPC_H
#define IPC_H

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#endif

typedef enum { ALLOW, DENY } Action;

typedef struct
{
  char source_addr[INET_ADDRSTRLEN];
  char dest_addr[INET_ADDRSTRLEN];
  int source_port;
  int dest_port;
  Action action;
} Message;

int init_ipc(void);
int send_ipc_message(Message *message);
int recv_ipc_message(Message *message);

#endif
