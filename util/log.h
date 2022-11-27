#ifndef UNOVA_UTIL_LOG_H_
#define UNOVA_UTIL_LOG_H_

#include <glog/logging.h>
#include <glog/raw_logging.h>

// 原来的 DLOG_ASSERT 在 NDEBUG 模式下有问题
#undef DLOG_ASSERT

#ifndef NDEBUG

#define DLOG_ASSERT(condition) LOG_ASSERT(condition)
#define RAW_DVLOG(verboselevel, ...)  RAW_VLOG(verboselevel, __VA_ARGS__)

#else  // NDEBUG

#define DLOG_ASSERT(condition) \
    static_cast<void>(0),        \
    (true || !(condition)) ? (void) 0 : google::LogMessageVoidify() & LOG(FATAL)
#define RAW_DVLOG(verboselevel, ...) \
    static_cast<void>(0), \
    (true || (VLOG_IS_ON(verboselevel))) ? (void) 0 : (RAW_LOG_INFO(__VA_ARGS__))

#endif  // NDEBUG

#define d_info      DLOG(INFO)
#define d_warning   DLOG(WARNING)
#define d_error     DLOG(ERROR)
#define d_fatal     DLOG(FATAL)

// 线程、过程信息
#define dv_proc     DVLOG(0)
// 模块信息
#define dv_mod      DVLOG(1)
// 函数信息
#define dv_func     DVLOG(2)
// 低级详细信息
#define dv_verb     DVLOG(3)

// 注意raw log不受FLAGS_minloglevel和vlog_level的控制。
#define rd_info(...)     RAW_DLOG(INFO, __VA_ARGS__)
#define rd_warning(...)  RAW_DLOG(WARNING, __VA_ARGS__)
#define rd_error(...)    RAW_DLOG(ERROR, __VA_ARGS__)
#define rd_fatal(...)    RAW_DLOG(FATAL, __VA_ARGS__)

#define rdv_proc(...)    RAW_DVLOG(0, __VA_ARGS__)
#define rdv_mod(...)     RAW_DVLOG(1, __VA_ARGS__)
#define rdv_func(...)    RAW_DVLOG(2, __VA_ARGS__)
#define rdv_verb(...)    RAW_DVLOG(3, __VA_ARGS__)

#define dlog_assert(condition) DLOG_ASSERT(condition)

// NDEBUG

#define info      LOG(INFO)
#define warning   LOG(WARNING)
#define error     LOG(ERROR)
#define fatal     LOG(FATAL)

// 线程、过程信息
#define v_proc     VLOG(0)
// 模块信息
#define v_mod      VLOG(1)
// 函数信息
#define v_func     VLOG(2)
// 低级详细信息
#define v_verb     LOG(3)

#define r_info(...)     RAW_LOG(INFO, __VA_ARGS__)
#define r_warning(...)  RAW_LOG(WARNING, __VA_ARGS__)
#define r_error(...)    RAW_LOG(ERROR, __VA_ARGS__)
#define r_fatal(...)    RAW_LOG(FATAL, __VA_ARGS__)

#define rv_proc(...)    RAW_VLOG(0, __VA_ARGS__)
#define rv_mod(...)     RAW_VLOG(1, __VA_ARGS__)
#define rv_func(...)    RAW_VLOG(2, __VA_ARGS__)
#define rv_verb(...)    RAW_VLOG(3, __VA_ARGS__)

#define log_assert(condition) LOG_ASSERT(condition)

struct LogCfg {
    bool is_log_to_stderr;
    int vlog_level;
    int min_log_level;
};

void InitLog(const char* argv0, LogCfg* cfg);

// #undef LOG;
// #undef VLOG;
// #undef RAW_LOG;
// #undef RAW_DLOG;
// #undef DLOG;
// #undef DVLOG;
// #undef RAW_VLOG;
// #undef RAW_DVLOG;

#endif // UNOVA_UTIL_LOG_H_
