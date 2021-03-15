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
#include <arpa/inet.h>
#include <mqueue.h>
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

#ifndef _WIN32
int main(void)
{
  struct msg m;
  strcpy(m.source_addr, "192.168.2.2");
  strcpy(m.dest_addr, "127.0.0.1");
  m.source_port = 69;
  m.dest_port = 420;
  m.action = ALLOW;

  mqd_t queue = mq_open("/yeet", O_RDWR);  

  printf("mq_open: %d\n", queue);
  perror("error");

  int s = mq_send(queue, (void*)&m, sizeof(struct msg), 0);

  printf("mq_send: %d\n", s);
  perror("error");

  mq_close(queue);
  return 0;
}
#else

int main(void)
{
  HANDLE pipe = CreateFile(
			   TEXT("\\\\.\\pipe\\dfw"),
			   PIPE_ACCESS_DUPLEX,
			   PIPE_TYPE_MESSAGE,
			   NULL,
			   OPEN_EXISTING,
			   FILE_ATTRIBUTE_NORMAL,
			   NULL);

  if(pipe == INVALID_HANDLE_VALUE)
    {
      printf("error connecting to pipe\n");
      return 1;
    }

  wchar_t *data = L"Hello pipes!";
  DWORD bytes_written = 0;
  BOOL result = WriteFile(
			  pipe,
			  data,
			  wcslen(data) * sizeof(wchar_t),
			  &bytes_written,
			  NULL);
  
  if(result)
    {
      printf("wrote %lu bytes\n", bytes_written);
    }
  else
    {
      printf("error sending\n");
    }

  CloseHandle(pipe);

  return 0;

}

#endif
