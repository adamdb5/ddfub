#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <mqueue.h>
#include <arpa/inet.h>
#endif

enum Action { ALLOW, DENY };
typedef enum Action Action;

struct msg
{
  char source_addr[INET_ADDRSTRLEN];
  char dest_addr[INET_ADDRSTRLEN];
  int  source_port;
  int  dest_port;
  Action action;
};

static int end = 0;

#ifndef _WIN32
static mqd_t msg_queue;
void received(int dummy)
{
  char buffer[sizeof(struct msg)];
  struct msg m;
  printf("Polling!\n");
  int s = mq_receive(msg_queue, buffer, sizeof(struct msg), 0);

  printf("mq_receive: %d\n", s);
  perror("");

  memcpy(&m, buffer, sizeof(struct msg));
  printf("Source addr: %s\n", m.source_addr);
  end = 1;
}

int main(void)
{
  struct mq_attr attr;
  attr.mq_flags = 0;
  attr.mq_maxmsg = 2;
  attr.mq_msgsize = sizeof(struct msg);
  attr.mq_curmsgs = 0;
  mqd_t queue = mq_open("/dfw", O_CREAT | O_RDWR, 0644, &attr);
  printf("mq_open: %d\n", queue);
  perror("");
  msg_queue = queue;

  //struct sigevent evt;
  //evt.sigev_notify = SIGEV_SIGNAL;
  //evt.sigev_signo = SIGALRM;
  //mq_notify(queue, &evt);
  //signal(SIGALRM, received);
  //while(!end);
  received(0);
  mq_unlink("/yeet");
  return 0;
}
#else

int main(void)
{
  HANDLE pipe = CreateNamedPipe(
				TEXT("\\\\.\\pipe\\dfw"),
				PIPE_ACCESS_DUPLEX,
				PIPE_TYPE_MESSAGE,
				1,
				0,
				0,
				0,
				NULL);
  
  if(pipe == NULL || pipe == INVALID_HANDLE_VALUE)
    {
      printf("error creating pipe\n");
    }
  
  BOOL result = ConnectNamedPipe(pipe, NULL);
  if(!result)
  {
    printf("error connecting to pipe\n");
    CloseHandle(pipe);
  }

  wchar_t buffer[128];
  char c_buffer[128];
  DWORD bytes_read = 0;
  result = ReadFile(
			 pipe,
			 buffer,
			 127 * sizeof(wchar_t),
			 &bytes_read,
			 NULL);

  if(!result)
    {
      printf("failed to read from pipe\n");
    }
  else
    {
      WideCharToMultiByte(CP_ACP, 0, buffer, wcslen(buffer), c_buffer, 128, NULL, NULL);
      printf("buffer: %s\n", c_buffer);
    }

  CloseHandle(pipe);
}

#endif
