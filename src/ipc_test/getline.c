#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <mqueue.h>

#include "../ipc.h"

int main(void)
{
  char *buffer_ptr;
  ssize_t written;

  printf("+----------------------------------------+\n");
  printf("|    Decentralised Firewall Interface    |\n");
  printf("|             Adam Bruce 2021            |\n");
  printf("+----------------------------------------+\n");
  //while(1)
    {
      buffer_ptr = NULL;
      written = 0;
      printf("dfw>");
      getline(&buffer_ptr, &written, stdin);

      printf("you typed: %s\n", buffer_ptr);
      free(buffer_ptr);
    }

  return 0;
}
