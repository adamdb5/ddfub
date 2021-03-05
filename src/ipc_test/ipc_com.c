#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "../ipc.h"

int main(void)
{
  IPCMessage m;
  char *buffer;
  ssize_t bytes_read;
  int running = 1;
  
  memset(&m, 0, sizeof(m));
  init_ipc_client();
  printf("Client ready\n");

  while(running)
    {
      buffer = NULL;
      bytes_read = 0;
      printf("dfw>");
      getline(&buffer, &bytes_read, stdin);

      printf("buffer: %s\n", buffer);
      
      if(strlen(buffer) >= 4 && strncmp(buffer, "quit", 4) == 0)
	{
	  printf("quitting...\n");
	  running = 0;
	}
      if(strlen(buffer) >= 4 && strncmp(buffer, "rule", 4) == 0)
	{
	  printf("m.message_type = RULE\n");
	  m.message_type = RULE;
	}
      if(strlen(buffer) >= 6 && strncmp(buffer, "enable", 6) == 0)
	{
	  printf("m.message_type = ENABLE\n");
	  m.message_type = ENABLE;
	}
      if(strlen(buffer) >= 7 && strncmp(buffer, "disable", 7) == 0)
	{
	  printf("m.message_type = DISABLE\n");
	  m.message_type = DISABLE;
	}
      if(strlen(buffer) >= 8 && strncmp(buffer, "shutdown", 8) == 0)
	{
	  printf("m.message_type = SHUTDOWN\n");
	  m.message_type = SHUTDOWN;
	}
      free(buffer);
      send_ipc_message(&m);
    }

  cleanup_ipc();
  return 0;
}
