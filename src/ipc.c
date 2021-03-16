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
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <mqueue.h>
#endif

#ifdef _WIN32
static HANDLE queue;
#else
static mqd_t queue;
#endif

#ifdef _WIN32
int init_ipc_server(void)
{
  HANDLE mqueue;

  mqueue = CreateNamedPipe(TEXT("\\\\.\\pipe\\dfw"), PIPE_ACCESS_DUPLEX,
				PIPE_TYPE_MESSAGE, 1, 0, 0, 0, NULL);

  if(!mqueue || mqueue == INVALID_HANDLE_VALUE)
    {
      return 1;
    }

  queue = mqueue;

  return 0;
}

int connect_ipc(void)
{
  if(!ConnectNamedPipe(queue, NULL))
    {
      CloseHandle(queue);
      return 1;
    }
  return 0;
}

int init_ipc_client(void)
{
  HANDLE mqueue;

  mqueue = CreateFile(TEXT("\\\\.\\pipe\\dfw"), PIPE_ACCESS_DUPLEX,
		      PIPE_TYPE_MESSAGE, NULL, OPEN_EXISTING,
		      FILE_ATTRIBUTE_NORMAL, NULL);

  if(mqueue == INVALID_HANDLE_VALUE)
    {
      return 1;
    }

  queue = mqueue;
  
  return 0;
}

int cleanup_ipc(void)
{
  return CloseHandle(queue);
}

int send_ipc_message(IPCMessage *message)
{
  DWORD bytes_sent = 0;
  BOOL result = FALSE;

  result = WriteFile(queue, message, sizeof(message), &bytes_sent, NULL);
  if(!result)
    {
      return 1;
    }
  
  return 0;
}

int recv_ipc_message(IPCMessage *message)
{
  DWORD bytes_read = 0;
  BOOL result = FALSE;

  result = ReadFile(queue, message, sizeof(message), &bytes_read, NULL);

  if(!result)
    {
      return 1;
    }
  return 0;
}

#else
int init_ipc_server(void)
{
  struct mq_attr attr;
  mqd_t mqueue;
  
  attr.mq_flags = 0;
  attr.mq_maxmsg = 2;
  attr.mq_msgsize = sizeof(IPCMessage);
  attr.mq_curmsgs = 0;
  mqueue = mq_open("/dfw", O_CREAT | O_RDWR, 0644, &attr);

  if(mqueue == (mqd_t)-1)
    {
      return 1;
    }

  queue = mqueue;
  return 0;
}

int init_ipc_client(void)
{
  mqd_t mqueue;

  mqueue = mq_open("/dfw", O_RDWR);

  if(mqueue == (mqd_t)-1)
    {
      return 1;
    }

  queue = mqueue;
  return 0;
}

int cleanup_ipc(void)
{
  return mq_close(queue);
}

int send_ipc_message(IPCMessage *message)
{
  if(mq_send(queue, (void*)message, sizeof(message), 0) == -1)
    {
      return 1;
    }
  return 0;
}

int recv_ipc_message(IPCMessage *message)
{
  if(mq_receive(queue, (void*)message, sizeof(IPCMessage), 0) == -1)
    {
      return 1;
    }
  
  return 0;
}
#endif

