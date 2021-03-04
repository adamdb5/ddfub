/**
 * @file main.c
 * @brief Entry point for the application.
 * @author Adam Bruce
 * @date 15 Dec 2020
 */

#include "net.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
  char buffer[100];

  init_net();
  while(1)
    {
      memset(buffer, '\0', 100);
      poll_message(buffer, 100);
    }
  cleanup_net();
  
  return 0;
}
