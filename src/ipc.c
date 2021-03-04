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

#ifdef _WIN32
static HANDLE queue;
#else
static mqd_t queue;
#endif

#ifdef _WIN32
int init_ipc(void)
{
  HANDLE mqueue;

  mqueue = CreateNamedPipe(TEXT("\\\\.\\pipe\\dfw"), PIPE_ACCESS_DUPLEX,
				PIPE_TYPE_MESSAGE, 1, 0, 0, 0, NULL);

  if(!mqueue || mqueue == INVALID_HANDLE_VALUE)
    {
      return 1;
    }

  if(!ConnectNamedPipe(mqueue, NULL))
    {
      CloseHandle(mqueue);
      return 1;
    }

  queue = mqueue;

  return 0;
}

int send_ipc_message(Message *message)
{
  DWORD bytes_sent = 0;
  BOOL result = FALSE;

  result = WriteFile(queue, message, sizeof(struct Message), &bytes_sent, NULL);
  if(!result)
    {
      return 1;
    }
  
  return 0;
}

int recv_ipc_message(Message *message)
{
  DWORD bytes_read = 0;
  BOOL result = FALSE;

  result = ReadFile(queue, message, sizeof(Message), &bytes_read, NULL);

  if(!result)
    {
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

int send_ipc_message(Message *message)
{
  if(mq_send(queue, (void*)message, sizeof(Message), 0) == -1)
    {
      return 1;
    }
  return 0;
}

int recv_ipc_message(Message *message)
{
  if(mq_receive(queue, (void*)message, sizeof(Message), 0) == -1)
    {
      return 1;
    }
  return 0;
}
#endif

