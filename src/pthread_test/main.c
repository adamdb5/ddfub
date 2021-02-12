#include <pthread.h>
#include <stdio.h>

void *func(void *data)
{
  int *number = (int*)data;
  (*number)++;
  return NULL;
}

int main(void)
{
  pthread_t func_thread;
  int number = 1;

  if(pthread_create(&func_thread, NULL, func, &number))
    {
      perror("Error creating thread");
      return 1;
    }

  if(pthread_join(func_thread, NULL))
    {
      perror("Error joining thread");
      return 1;
    }

  printf("Number: %d\n", number);
  
  return 0;
}
