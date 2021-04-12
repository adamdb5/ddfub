#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/time.h>
#endif
#include <stdio.h>
#include "timer.h"

#ifdef _WIN32
void timer(void)
{
        SYSTEMTIME st;
        GetSystemTime(&st);
        printf("%lu.%lu\n", st.wSecond, st.wMilliseconds);
}
#else
void timer(void)
{
	struct timeval current_time;
	gettimeofday(&current_time, NULL);
	printf("%lu.%lu\n", current_time.tv_sec, current_time.tv_usec);
}
#endif
