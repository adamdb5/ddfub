#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "../ipc.h"

int main(void)
{
  IPCMessage m;
  char buffer[100];
  int running = 1;
  
  init_ipc_client();
  printf("****************************************************************\n");
  printf("*             Decentralised Firewall IPC Interface             *\n");
  printf("*                        by Adam Bruce                         *\n");
  printf("****************************************************************\n");

  printf("\nAvailable commands:\n");
  printf("  enable   :  Enables communication over the network.\n");
  printf("  disable  :  Disables communication over the network.\n");
  printf("  rule     :  Generates a new block containing the rule,\n");
  printf("              and broadcasts the block for consensus.\n");
  printf("  shutdown :  Terminates the framework.\n");
  printf("  quit     :  Quits this program.\n\n");
  while(running)
    {
      printf("dfw>");
      memset(buffer, 0, 100);
      memset(&m, 0, sizeof(IPCMessage));
      scanf("%s", buffer);
      
      if(strlen(buffer) >= 4 && strncmp(buffer, "quit", 4) == 0)
	{
	  running = 0;
	}
      else if(strlen(buffer) >= 4 && strncmp(buffer, "rule", 4) == 0)
	{
	  scanf("%s", m.rule.source_addr);
	  scanf("%hd", &m.rule.source_port);
	  scanf("%s", m.rule.dest_addr);
	  scanf("%hd", &m.rule.dest_port);
	  scanf("%s", buffer);

	  m.rule.action = DENY;
	  if(strncmp(buffer, "ALLOW", 5) == 0 ||
	     strncmp(buffer, "allow", 5) == 0)
	    {
	      m.rule.action = ALLOW;
	    }

	  m.message_type = I_RULE;

	  printf("Sending firewall rule to daemon:\n");
	  printf("    Source Address:      %s\n", m.rule.source_addr);
	  printf("    Source Port:         %hd\n", m.rule.source_port);
	  printf("    Destination Address: %s\n", m.rule.dest_addr);
	  printf("    Destination Port:    %hd\n", m.rule.dest_port);
	  printf("    Action:              %s\n",
		 (m.rule.action == ALLOW ? "ALLOW" : "DENY"));

	  send_ipc_message(&m);
	}
      else if(strlen(buffer) >= 6 && strncmp(buffer, "enable", 6) == 0)
	{
	  printf("Sending Enable message to daemon\n");
	  m.message_type = I_ENABLE;
	  send_ipc_message(&m);
	}
      else if(strlen(buffer) >= 7 && strncmp(buffer, "disable", 7) == 0)
	{
	  printf("Sending Disable message to daemon\n");
       	  m.message_type = I_DISABLE;
	  send_ipc_message(&m);
	}
      else if(strlen(buffer) >= 8 && strncmp(buffer, "shutdown", 8) == 0)
	{
	  printf("Sending Shutdown message to daemon\n");
	  m.message_type = I_SHUTDOWN;
	  send_ipc_message(&m);
	}
      else
	{
	  printf("Unknown command\n");
	}
    }

  printf("Bye!\n");
  cleanup_ipc();
  return 0;
}
