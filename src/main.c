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
  char buffer[11];
  while(!shutdown_flag)
    {
      memset(buffer, 0, 11);
      if(enabled_flag)
	{
	  poll_message(buffer, 11);
	}
#ifdef _WIN32
      Sleep(10);
#else
      usleep(10 * 1000);
#endif
    }
  return NULL;
}

int main(int argc, char** argv)
{
  IPCMessage ipc_msg;
  AdvertisementMessage adv_msg;
  pthread_t recv_thread;
  char local_addr[INET_ADDRSTRLEN];

  if(init_ipc_server())
    {
      perror("[ ERR  ] Failed to initialise IPC: ");
      return 1;
    }
  printf("[ INFO ] Initialised IPC\n");

  if(init_net())
    {
      cleanup_ipc();
      perror("[ ERR  ] Failed to initialise network stack: ");
      return 1;
    }
  printf("[ INFO ] Initialised network stack\n");
  load_hosts_from_file("hosts.txt");

  if(pthread_create(&recv_thread, NULL, recv_thread_func, NULL))
    {
      perror("[ ERR  ] Failed to initialise receiving thread: ");
      cleanup_net();
      cleanup_ipc();
      return 1;
    }
  printf("[ INFO ] Initialised receiving thread\n");

  if(get_host_count() > 0)
    {
      adv_msg.type = ADVERTISEMENT;
      adv_msg.hops = 0;
      adv_msg.advertisement_type = BROADCAST;
      get_local_address(local_addr);
      strncpy(adv_msg.source_addr, local_addr, INET_ADDRSTRLEN);
      send_to_all_advertisement_message(&adv_msg);
      printf("[ INFO ] Sent advertisement to %d known host(s)\n", get_host_count());
    }
  
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
	  printf("[ INFO ] Received IPC Message: Shutting down\n");
	  shutdown_flag = 1;
	  break;
	case I_ENABLE:
	  printf("[ INFO ] Received IPC Message: Enabling Transactions\n");
	  enabled_flag = 1;
	  break;
	case I_DISABLE:
	  printf("[ INFO ] Received IPC Message: Disabling Transactions\n");
	  enabled_flag = 0;
	  break;
	case I_RULE:
	  printf("[ INFO ] Received IPC Message: New Firewall Rule\n");
	  printf("RULE: %s %d %s %d %d\n",
		 ipc_msg.rule.source_addr,
		 ipc_msg.rule.source_port,
		 ipc_msg.rule.dest_addr,
		 ipc_msg.rule.dest_port,
		 ipc_msg.rule.action);
	  send_new_rule(&ipc_msg.rule);
  	  break;
	default:
	  printf("[ ERR  ] Recieved Unknown IPC Message Type\n");
	}
    }

  printf("[ INFO ] Waiting for receiving thread to terminate\n");
  pthread_join(recv_thread, NULL);

  cleanup_net();
  cleanup_ipc();
  return 0;
}
