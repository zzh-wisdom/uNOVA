#include "util/statistics.h"

uint64_t file_write_time = 0;
uint64_t pm_io_time = 0;
uint64_t log_io_time = 0;

void statistics_print() {
    printf("file_write_time=%lu us, pm_io_time=%lu us\n", file_write_time/1000, pm_io_time/1000);
    printf("pm_io_percentage=%0.2lf%\nlog_io_percentage=%0.2lf%\n",
        pm_io_time*100.0/file_write_time,
        log_io_time*100.0/file_write_time);
    printf("meta time=%lu us, %0.2lf%%\n",
        (file_write_time-pm_io_time)/1000, (file_write_time-pm_io_time)*100.0/file_write_time);
}
