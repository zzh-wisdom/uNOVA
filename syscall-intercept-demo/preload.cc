#include "hooks.h"

#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <libsyscall_intercept_hook_point.h>

static pthread_once_t init_ctx_thread = PTHREAD_ONCE_INIT;

static int cmdline_match(const char *filter, const char *cmdline)
{
	if (filter == NULL)
		return 1;

	size_t flen = strlen(filter);
	size_t clen = strlen(cmdline);

	if (flen > clen)
		return 0; /* cmdline can't contain filter */

	if (clen > flen && cmdline[clen - flen - 1] != '/')
		return 0;

	return strcmp(cmdline + clen - flen, filter) == 0;
}

int is_process_allowed(const char *cmdline)
{
	static bool is_decided;
	static int result;

	if (is_decided)
		return result;

	if (cmdline == NULL)
		return 0;

	result = cmdline_match(getenv("INTERCEPT_HOOK_CMDLINE_FILTER"), cmdline);
	is_decided = true;

	return result;
}

static __attribute__((constructor)) void preload(int argc, char **argv) {
    // 防止fork时多次初始化
	// 判断是否开启拦截吧
    // if (!is_process_allowed(argv[0]))
	// 	return;

    // 初始化工作
    // pthread_once(&init_ctx_thread, metafs::init_client_ctx);

    printf("preload ok\n");

    intercept_hook_point = wrapper_hook;

    #if HOOK_REWRITE
	init_rewrite_flag = true;
    #endif
}
