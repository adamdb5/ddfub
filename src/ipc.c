/**
 * @file ipc.c
 * @brief Inter-process Communication interface
 * @author Adam Bruce
 * @date 4 Mar 2021
 */

#include "ipc.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ws2tcpip.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <mqueue.h>
#include <arpa/inet.h>
#endif

#ifndef _WIN32
static mqd_t queue;
#endif

#ifdef _WIN32
int init_ipc(void)
{
  HANDLE pipe;

  pipe = CreateNamedPipe(TEXT("\\\\.\\pipe\\dfw"), PIPE_ACCESS_DUPLEX,
				PIPE_TYPE_MESSAGE, 1, 0, 0, 0, NULL);

  if(!pipe || pipe == INVALID_HANDLE_VALUE)
    {
      return 1;
    }

  if(!ConnectNamedPipe(pipe, NULL))
    {
      CloseHandle(pipe);
      return 1;
    }

  return 0;
}
#else
int init_ipc(void)
{
  struct mq_attr attr;
  mqd_t mqueue;
  
  attr.mq_flags = 0;
  attr.mq_maxmsg = 2;
  attr.mq_msgsize = sizeof(Message);
  attr.mq_curmsgs = 0;
  mqueue = mq_open("/dfw", O_CREAT | O_RDWR, 0644, &attr);

  if(mqueue == -1)
    {
      return 1;
    }

  return 0;
}
#endif
