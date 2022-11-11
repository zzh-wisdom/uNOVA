# syscall_intercept

用户空间**系统调用拦截库**。

## 运行时依赖

- libcapstone: hood时底下使用的拆解引擎。

## 本地构建（ubuntu）

一些依赖安装

```shell
sudo apt install cmake
sudo apt install clang
sudo apt-get install pkg-config libcapstone-dev
sudo apt install pandoc
```

---

编译安装

```shell
mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang
make -j8
sudo make install
```

## 如何使用

```c
#include <libsyscall_intercept_hook_point.h>
```

```shell
cc -lsyscall_intercept -fpic -shared source.c -o preloadlib.so

LD_PRELOAD=preloadlib.so ./application
```

系统调用拦截库提供了一个低级接口，用于在用户空间中挂接(hook) Linux 系统调用。这**是通过在进程的内存中热修补标准C库的机器代码来实现的**。此库的用户可以使用 libsyscall_intercept_hook_point.h 头文件中指定的非常简单的 API，在用户空间中提供几乎任何系统调用的功能：

```c
int (*intercept_hook_point)(long syscall_number,
			long arg0, long arg1,
			long arg2, long arg3,
			long arg4, long arg5,
			long *result);
```

库的用户应**将指针分配给名为 intercept_hook_point变量**，以指向回调函数的地址。**回调函数返回的非零返回值用于向拦截库发出信号，指示用户忽略了特定的系统调用，应执行原始的系统调用**。**零返回值表示用户接管系统调用**。在这种情况下，可以通过 *result 指针设置系统调用的结果（系统调用后存储在 RAX 寄存器中的值）。为了使用该库，应使用系统加载进程提供的LD_PRELOAD功能加载拦截代码。

LIBC 发出的所有系统调用都将被拦截。由 libc 外部的代码进行的系统调用不会被拦截。**为了能够发出未被拦截的系统调用，该库提供了一个方便的功能**：

```c
long syscall_no_intercept(long syscall_number, ...);
```

该函数指示对应的系统调用不被拦截，避免拦截的函数中，继续使用系统调用，导致死循环。

三个环境变量控制库的操作：

- **INTERCEPT_LOG** -- 设置后，库会将截获的每个系统调用记录到一个文档中。如果它以“-”结尾，则通过将进程ID附加到环境变量中提供的值来形成文档的路径。例如：当INTERCEPT_LOG设置为“intercept.log-”时，在带有pid 123的进程中初始化库将导致一个名为intercept.log-123的日志文档。
- **INTERCEPT_LOG_TRUNC** -- 设置为 0 时，不会截断INTERCEPT_LOG的日志文档。
- **INTERCEPT_HOOK_CMDLINE_FILTER** -- 设置后，库将检查用于启动进程的命令行。仅当用于**启动进程的命令**的最后一个组件（指argv[0]的最后一部分）与环境变量中提供的字符串相同时，才会进行热修补和 syscall 拦截。库用户也可以使用以下查询是否开启拦截：

```c
int syscall_hook_in_process_allowed(void);
```

"./somewhere/a.out" matches "a.out"
"./a.out" matches "a.out"
"./xa.out" does not match "a.out"

例如：

```shell
LD_PRELOAD=build/libdemo_hook.so INTERCEPT_HOOK_CMDLINE_FILTER=bin/test ./bin/test # 开启拦截
LD_PRELOAD=build/libdemo_hook.so INTERCEPT_HOOK_CMDLINE_FILTER=test ./bin/test # 开启拦截
LD_PRELOAD=build/libdemo_hook.so INTERCEPT_HOOK_CMDLINE_FILTER=est ./bin/test # 拦截未开启
```

### 样例

样例见 <https://github.com/pmem/syscall_intercept>

> -fPIC: 为了兼容各个系统，在生成位置无关的代码的时候，应该使用-fPIC参数。
> <https://blog.csdn.net/xiangguiwang/article/details/81939237>
>

## 参考

1. github pmem/syscall_intercept: <https://github.com/pmem/syscall_intercept>