# for hook
# ulimit -c unlimited

# LD_PRELOAD=build/libdemo_hook.so bin/test

sudo LD_PRELOAD=./libfs_hook.so ./fstest