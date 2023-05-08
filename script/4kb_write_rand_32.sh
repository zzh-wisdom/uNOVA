if [[ "$1" == "nova" ]]
then

sudo LD_PRELOAD=./libnova_hook.so numactl --cpunodebind=1 --membind=1 \
fio ../test/fio/nova_vary_threads.fio

elif [[ "$1" == "libnvmmio" ]]
then

cd ../../libnvmmio/evaluation/fio
sudo ./my_run.sh
cd ../../../uNOVA/build

elif [[ "$1" == "finefs-nolimit" ]]
then

sudo LD_PRELOAD=./libfinefs-nolimit_hook.so numactl --cpunodebind=1 --membind=1 \
fio ../test/fio/finefs_vary_threads.fio

else

sudo LD_PRELOAD=./libfinefs_hook.so numactl --cpunodebind=1 --membind=1 \
fio ../test/fio/finefs_vary_threads.fio

fi
