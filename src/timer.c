#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/time.h>
#endif
#include <stdio.h>
#include "timer.h"

#ifdef _WIN32
void timer(const char* msg)
{
        SYSTEMTIME st;
        GetSystemTime(&st);
        printf("%s: %lu.%lu\n", msg, st.wSecond, st.wMilliseconds);
}
#else
void timer(const char* msg)
{
	struct timeval current_time;
	gettimeofday(&current_time, NULL);
	printf("%s: %lu.%lu\n", msg, current_time.tv_sec, current_time.tv_usec);
}
#endif
