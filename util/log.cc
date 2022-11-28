#include "util/log.h"

#include <assert.h>

static bool is_init = false;

void InitLog(const char* argv0, LogCfg* cfg) {
    if(is_init) return;
    FLAGS_logtostderr = cfg->is_log_to_stderr;
    FLAGS_v = cfg->vlog_level;
    FLAGS_minloglevel = cfg->min_log_level;
    google::InitGoogleLogging(argv0);

    // some check
#ifdef NDEBUG
    printf("Run as [NOT DEBUG] mode\n");
    assert(0);
    DLOG(FATAL) << "DLOG UnExpected!!!";
    DVLOG(0) << "DVLOG UnExpected!!!";
    DLOG_ASSERT(0) << "DLOG_ASSERT UnExpected!!!";
    DLOG_IF(FATAL, 1) << "DLOG_IF UnExpected!!!";
    DLOG_EVERY_N(FATAL, 0) << "DLOG_EVERY_N UnExpected!!!";
    DLOG_IF_EVERY_N(FATAL, 1, 1) << "DLOG_IF_EVERY_N UnExpected!!!";
    DCHECK(0) << "DCHECK UnExpected!!!";
    DCHECK_STREQ("1", "2") << "DCHECK_STREQ UnExpected!!!";
    char* tmp_ptr = nullptr;
    DCHECK_NOTNULL(tmp_ptr);
    d_info << "d_info UnExpected!!!";
    d_warning << "d_warning UnExpected!!!";
    d_error << "d_error UnExpected!!!";
    d_fatal << "d_fatal UnExpected!!!";
    dv_proc << "dv_proc UnExpected!!!";
    dv_mod << "dv_mod UnExpected!!!";
    dv_func << "dv_func UnExpected!!!";
    dv_verb << "dv_verb UnExpected!!!";
    rd_info("%s\n", "rd_info UnExpected!!!");
    rd_warning("%s\n", "rd_warning UnExpected!!!");
    rd_error("%s\n", "rd_error UnExpected!!!");
    rd_fatal("%s\n", "rd_fatal UnExpected!!!");
    rdv_proc("%s\n", "rdv_proc UnExpected!!!");
    rdv_mod("%s\n", "rdv_mod UnExpected!!!");
    rdv_func("%s\n", "rdv_func UnExpected!!!");
    rdv_verb("%s\n", "rdv_verb UnExpected!!!");
    dlog_assert(0) << "dlog_assert UnExpected!!!";
#else
    printf("Run as [DEBUG] mode\n");
    DLOG_ASSERT(1) << "DLOG_ASSERT UnExpected!!!";
    dlog_assert(1) << "dlog_assert UnExpected!!!";
#endif
}
