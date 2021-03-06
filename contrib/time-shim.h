/* librist. Copyright 2019 SipRadius LLC. All right reserved.
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */

#ifndef __TIME_SHIM_H
#define __TIME_SHIM_H

#if defined(_WIN32)
#define usleep(a)	Sleep((a)/1000)
# include <winsock2.h>
# include <time.h>

# define CLOCK_MONOTONIC 1

typedef int clockid_t;
int gettimeofday(struct timeval *tv, void * not_implemented);

typedef struct timespec timespec_t;
int clock_gettime(clockid_t clock, timespec_t *tp);

#elif defined(__APPLE__)
#include <mach/mach_time.h>
typedef mach_timespec_t timespec_t;
int clock_gettime_osx(timespec_t *ts);

#else
# include <sys/time.h>
# include <time.h>
typedef struct timespec timespec_t;
#endif

#endif
