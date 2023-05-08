
#include "finefs/finefs_def.h"

const int FINEFS_NVM_READ_MAX_THREADS = 6;
const int FINEFS_NVM_WRITE_MAX_THREADS = 4;
// TODO：读写分别判断，分别设置参数
const int FINEFS_LIMIT_NVM_THREAD_SIZE = 128;  // 用来测试的，大于该大小的读写则进行线程限制