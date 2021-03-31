/**
 * @file main.c
 * @brief Entry point for the application.
 * @author Adam Bruce
 * @date 22 Mar 2021
 */

#include "firewall.h"
#include "net.h"
#include "ipc.h"
#include "blockchain.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#define HAVE_STRUCT_TIMESPEC /* Prevent pthread from redefining timespec */
#else
#include <unistd.h>
#endif

#include <pthread.h>

/* Flags */
static int enabled_flag = 1;
static int shutdown_flag = 0;

/**
 * @brief Receiving thread.
 *
 * This function is automatically run on the second thread, receiving and
 * processing data from the network.
 */
void *recv_thread_func(void *data)
{
  char buffer[sizeof(RuleMessage)];
  while(!shutdown_flag)
    {
      memset(buffer, 0, sizeof(RuleMessage));
      if(enabled_flag)
	{
	  poll_message(buffer, sizeof(RuleMessage));
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

  /* Initialise IPC */
  if(init_ipc_server())
    {
      perror("[ IPC  ] Failed to initialise IPC");
      return 1;
    }
  printf("[ IPC  ] Initialised IPC\n");

  /* Initialise the network stack */
  if(init_net())
    {
      cleanup_ipc();
      perror("[ ERR  ] Failed to initialise network stack");
      return 1;
    }
  printf("[ NET  ] Initialised network stack\n");
  load_hosts_from_file("hosts.txt");

  /* Load any stored blocks */
  load_blocks_from_file("chain.txt");

  /* Create the receiving thread */
  if(pthread_create(&recv_thread, NULL, recv_thread_func, NULL))
    {
      perror("[ ERR  ] Failed to initialise receiving thread");
      cleanup_net();
      cleanup_ipc();
      return 1;
    }
  printf("[ INFO ] Initialised receiving thread\n");

  /* Send advertisement when joining the network */
  if(get_host_count() > 0)
    {
      adv_msg.type = ADVERTISEMENT;
      adv_msg.hops = 0;
      adv_msg.advertisement_type = BROADCAST;
      get_local_address(local_addr);
      strncpy(adv_msg.source_addr, local_addr, INET_ADDRSTRLEN);
      send_to_all_advertisement_message(&adv_msg);
      printf("[ ADV  ] Sent advertisement to %d known host(s)\n",
	     get_host_count());
    }
  
#ifdef _WIN32
  connect_ipc();
#endif

  printf("[ INFO ] Ready\n");

  /* Process IPC commands */
  while(!shutdown_flag)
    { 
      memset(&ipc_msg, 0, sizeof(IPCMessage));
      recv_ipc_message(&ipc_msg);

       switch(ipc_msg.message_type)
	{
	case I_SHUTDOWN:
	  printf("[ IPC  ] Received IPC Message: Shutting down\n");
	  shutdown_flag = 1;
	  break;
	case I_ENABLE:
	  printf("[ IPC  ] Received IPC Message: Enabling Transactions\n");
	  enabled_flag = 1;
	  break;
	case I_DISABLE:
	  printf("[ IPC  ] Received IPC Message: Disabling Transactions\n");
	  enabled_flag = 0;
	  break;
	case I_RULE:
	  printf("[ IPC  ] Received IPC Message: New Firewall Rule\n");
	  send_new_rule(&ipc_msg.rule);
  	  break;
	default:
	  printf("[ ERR  ] Recieved Unknown IPC Message Type\n");
	}
    }

  /* Cleanup and terminate */
  printf("[ INFO ] Waiting for receiving thread to terminate\n");
  pthread_join(recv_thread, NULL);
  cleanup_net();
  cleanup_ipc();
  free_chain();
  return 0;
}
