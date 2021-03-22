/**
 * @file main.c
 * @brief Entry point for the application.
 * @author Adam Bruce
 * @date 22 Mar 2021
 */

#include "net.h"
#include "ipc.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#define HAVE_STRUCT_TIMESPEC /* Prevent pthread from redefining timespec */
#else
#include <unistd.h>
#endif

#include <pthread.h>

static int enabled_flag = 1;
static int shutdown_flag = 0;

void *recv_thread_func(void *data)
{
  char buffer[sizeof(RuleMessage)];
  while(!shutdown_flag)
    {
      memset(buffer, 0, sizeof(RuleMessage));
      if(enabled_flag)
	{
	  printf("recv_thread_func()\n");
	  poll_message(buffer, sizeof(RuleMessage));
	}
#ifdef _WIN32
      Sleep(10);
#else
      usleep(10 * 1000);
#endif
    }
  printf("recv_thread_func() terminated\n");
  return NULL;
}

int main(int argc, char** argv)
{
  IPCMessage ipc_msg;
  pthread_t recv_thread;

  if(init_ipc_server())
    {
      perror("");
      return 1;
    }
  printf("IPC Initialised.\n");

  if(init_net())
    {
      cleanup_ipc();
      perror("");
      return 1;
    }
  printf("Network Stack Initialised.\n");

  if(pthread_create(&recv_thread, NULL, recv_thread_func, NULL))
    {
      perror("");
      cleanup_net();
      cleanup_ipc();
      return 1;
    }
  printf("[ INFO ] Receiving thread Initialised\n");

#ifdef _WIN32
  connect_ipc();
#endif
  
  while(!shutdown_flag)
    { 
      memset(&ipc_msg, 0, sizeof(IPCMessage));
      recv_ipc_message(&ipc_msg);

       switch(ipc_msg.message_type)
	{
	case I_SHUTDOWN:
	  printf("Shutting down\n");
	  shutdown_flag = 1;
	  break;
	case I_ENABLE:
	  printf("Transacations have been enabled\n");
	  enabled_flag = 1;
	  break;
	case I_DISABLE:
	  printf("Transaction have been disabled\n");
	  enabled_flag = 0;
	  break;
	case I_RULE:
	  printf("Received local firewall rule\n");
	  send_new_rule(&ipc_msg.rule);
  	  break;
	default:
	  printf("Unknown IPC message type.\n");
	}
    }

  printf("Waiting for receiving thread to terminate\n");
  pthread_join(recv_thread, NULL);

  cleanup_net();
  cleanup_ipc();
  return 0;
}
