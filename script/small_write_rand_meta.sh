if [[ "$1" == "libnvmmio" ]]
then
sudo LD_PRELOAD=../../libnvmmio/src/libnvmmio.so numactl --cpunodebind=1 --membind=1  ./small_write_rand $1 $2 1000000
else
sudo ./small_write_rand $1 $2 1000000
fi
