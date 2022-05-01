#!/bin/bash

LOG_DIR=results/benchmark
n_passwords=20
passwords=$(cat data/1000_passwords.txt | tr ' ' '\n' | shuf -n $n_passwords)
n_tests=1
mkdir -p $LOG_DIR

make --quiet clean clean_bin || true
make CFLAGS="-DPERF -O3" --quiet -j 
make --quiet DEBUG=1

echo "Testing legacy"
i=0
for p in $passwords; do
    ((i++))
    printf "\r\t\033[KTest $i/$n_passwords ($p)"
    sudo perf stat -r $n_tests --cpu=1 -- nice -n -20 taskset -c 1 bin/sae_dragonfly $p 2>> $LOG_DIR/legacy-openssl.perf
#    sudo perf stat -r $n_tests --cpu=1 -- nice -n -20 taskset -c 1 bin/sae_dragonfly-noasm $p 2>> $LOG_DIR/legacy-openssl_noasm.perf
    sudo perf stat -r $n_tests --cpu=1 -- nice -n -20 taskset -c 1 bin/sae_dragonstar $p 2>> $LOG_DIR/legacy-hacl.perf
done
echo -e "\n"
echo -e "\nTesting sswu"
i=0
for p in $passwords; do
    ((i++))
    printf "\r\t\033[KTest $i/$n_passwords ($p)"
    sudo perf stat -r $n_tests --cpu=1 -- nice -n -20 taskset -c 1 bin/sae_dragonfly -i testid $p 2>> $LOG_DIR/sswu-openssl.perf
#    sudo perf stat -r $n_tests --cpu=1 -- nice -n -20 taskset -c 1 bin/sae_dragonfly-noasm -i testid $p 2>> $LOG_DIR/sswu-openssl_noasm.perf
    sudo perf stat -r $n_tests --cpu=1 -- nice -n -20 taskset -c 1 bin/sae_dragonstar -i testid $p 2>> $LOG_DIR/sswu-hacl.perf
done
echo -e "\n"

sudo chown -R 1000:1000 $LOG_DIR
python3 scripts/perf_evaluation/parse_perf.py $LOG_DIR/*.perf

python3 scripts/perf_evaluation/plot.py $LOG_DIR/*.cycles &
python3 scripts/perf_evaluation/plot.py $LOG_DIR/*.instructions &
python3 scripts/perf_evaluation/plot.py $LOG_DIR/*.time &

echo "Graphs available in the shared_folder"