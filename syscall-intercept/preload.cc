#include <libsyscall_intercept_hook_point.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "hooks.h"
#include "util/common.h"
#include "util/log.h"
#include "util/statistics.h"

static pthread_once_t init_ctx_thread = PTHREAD_ONCE_INIT;

static int cmdline_match(const char *filter, const char *cmdline) {
    if (filter == NULL) return 1;

    size_t flen = strlen(filter);
    size_t clen = strlen(cmdline);

    if (flen > clen) return 0; /* cmdline can't contain filter */

    if (clen > flen && cmdline[clen - flen - 1] != '/') return 0;

    return strcmp(cmdline + clen - flen, filter) == 0;
}

int is_process_allowed(const char *cmdline) {
    static bool is_decided;
    static int result;

    if (is_decided) return result;

    if (cmdline == NULL) return 0;

    result = cmdline_match(getenv("INTERCEPT_HOOK_CMDLINE_FILTER"), cmdline);
    is_decided = true;

    return result;
}

ATTR_CONSTRUCTOR void preload(int argc, char **argv) {
    // 防止fork时多次初始化
    // 判断是否开启拦截吧
    // if (!is_process_allowed(argv[0]))
    // 	return;

    // 初始化工作
    LogCfg log_cfg = {
        .is_log_to_stderr = true,
        .vlog_level = 0,
        .min_log_level = 3,
    };
    InitLog(argv[0], &log_cfg);
    // char *hook_fs = getenv("HOOK_FS");
    // if (hook_fs == nullptr) {
    //     hook_op = &hook_op_native;
    // } else if (strcmp(hook_fs, "nova") == 0) {
    //     hook_op = &hook_op_nova;
    // } else if (strcmp(hook_fs, "finefs") == 0) {
    //     hook_op = &hook_op_finefs;
    // } else {
    //     hook_op = &hook_op_native;
    // }
#if FS_HOOK==1
    hook_op = &hook_op_nova;
#elif FS_HOOK==2
    hook_op = &hook_op_finefs;
#else
    hook_op = &hook_op_native;
#endif

	static const std::string dev_name = "/dev/dax1.0";
    printf("HOOK [%s], dev_name:[%s] root_path:[%s]\n", hook_op->label.c_str(), dev_name.c_str(),
           hook_op->root_name.c_str());
    // 创建fs
    int ret = hook_op->fs_init(&hook_op->sb, dev_name, hook_op->root_name);
    log_assert(ret == 0);
    // pthread_once(&init_ctx_thread, metafs::init_client_ctx);

    printf("preload ok\n");

    init_is_hook_flag();
    intercept_hook_point = wrapper_hook;

#if HOOK_REWRITE
    init_rewrite_flag = true;
#endif
}

ATTR_DESTRUCTOR void destroy() {
    int ret = hook_op->fs_unmount(&hook_op->sb, hook_op->root_name);
    log_assert(ret == 0);
    statistics_print();
}