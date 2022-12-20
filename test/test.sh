# for hook
# ulimit -c unlimited

# LD_PRELOAD=build/libdemo_hook.so bin/test

sudo LD_PRELOAD=./libnova_hook.so ./fstest
sudo LD_PRELOAD=./libfinefs_hook.so ./finefs_fstest

sudo LD_PRELOAD=./libnova_hook.so  fio ../test/fio/fio-seq_read.fio
sudo LD_PRELOAD=./libfinefs_hook.so  fio ../test/fio/fio-seq_read.fio

sudo LD_PRELOAD=./libfinefs_hook.so ./perf_ftruncate finefs 1

sudo LD_PRELOAD=./libfinefs_hook.so  fio ../test/fio/finefs_4k_base.fio
sudo LD_PRELOAD=./libnova_hook.so  fio ../test/fio/nova_4k_base.fio

sudo LD_PRELOAD=./libnova_hook.so filebench -f ../test/filebench/mywebserver.f
