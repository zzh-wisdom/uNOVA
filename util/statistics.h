#ifndef UNOVA_UTIL_STATISTICS_H_
#define UNOVA_UTIL_STATISTICS_H_

#include "util/cpu.h"

#include <stdint.h>

#define MEASURE_TIMING 1

extern uint64_t file_write_time;
extern uint64_t pm_io_time;
extern uint64_t log_io_time;

#ifdef MEASURE_TIMING
#define STATISTICS_START_TIMING(name, start) \
	do { start = GetTsNsec(); } while(0)

#define STATISTICS_END_TIMING(name, start) \
	do { \
		sfence(); \
        uint64_t end = GetTsNsec(); \
		name += end - start; \
    } while(0)

#else

#define NOVA_START_TIMING(name, start) void(0)
#define NOVA_END_TIMING(name, start) void(0)

#endif

void statistics_print();

#endif
