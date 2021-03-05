/**
 * @file main.c
 * @brief Entry point for the application.
 * @author Adam Bruce
 * @date 15 Dec 2020
 */

#include "ipc.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
  IPCMessage msg;
  int running = 1;
  int enabled = 1;

  if(init_ipc_server())
    {
      perror("");
      return 1;
    }
  else
    {
      printf("Firewall IPC Initialised.\n");
    }
  
  while(running)
    {
      memset(&msg, 0, sizeof(IPCMessage));
      recv_ipc_message(&msg);
      
      switch(msg.message_type)
	{
	case SHUTDOWN:
	  printf("Shutting down\n");
	  running = 0;
	  break;
	case ENABLE:
	  printf("Enabling\n");
	  enabled = 1;
	  break;
	case DISABLE:
	  printf("Disabling\n");
	  enabled = 0;
	  break;
	case RULE:
	  printf("New Firewall Rule\n");
	  /* Do firewall stuff */
  	  break;
	default:
	  printf("Unknown message type.\n");
	}
      
    }

  cleanup_ipc();
  return 0;
}
