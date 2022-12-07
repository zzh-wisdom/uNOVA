
sudo ./perf_mkdir finefs 100
sudo ./perf_open finefs  100
sudo ./perf_ftruncate finefs 100  1
sudo ./perf_write finefs 4096 100

# sudo ./perf_mkdir finefs 300000
# sudo ./perf_open finefs 300000
# sudo ./perf_ftruncate finefs 0 1
# sudo ./perf_write finefs 4096 1000000
