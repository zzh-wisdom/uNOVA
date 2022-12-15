
sudo ./perf_mkdir finefs 1000
sudo ./perf_open finefs  1000
sudo ./perf_ftruncate finefs 1000  1
sudo ./perf_write finefs 4096 1000
sudo ./perf_write finefs 64 1000

sudo ./finefs_fstest

# sudo ./perf_mkdir finefs 300000
# sudo ./perf_open finefs 300000
# sudo ./perf_ftruncate finefs 10000000 1
# sudo ./perf_write finefs 4096 1000000
