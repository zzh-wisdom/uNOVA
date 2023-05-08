if [[ "$1" == "nova" ]]
then

sudo numactl --cpunodebind=1 --membind=1 \
./varmail nova $2 200000

elif [[ "$1" == "libnvmmio" ]]
then

sudo numactl --cpunodebind=1 --membind=1 \
./varmail libnvmmio $2 200000

elif [[ "$1" == "finefs-nolimit" ]]
then

sudo numactl --cpunodebind=1 --membind=1 \
./varmail finefs-nolimit $2 200000

else

sudo numactl --cpunodebind=1 --membind=1 \
./varmail finefs $2 200000

fi
