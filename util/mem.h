#ifndef UNOVA_UTIL_MEM_H_
#define UNOVA_UTIL_MEM_H_

#include <stdlib.h>

#define ZALLOC(s) calloc(1, s)
#define MALLOC(s) malloc(s)
#define FREE(s) free(s)

#endif