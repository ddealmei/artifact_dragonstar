# Dragonstar: A plugin verified cryptographic implementation for Dragonfly

The PAKE Dragonfly is used as SAE(-PT) in WPA3 authentication. 

TODO: add a speech and link to hacl


## Repository layout

## Run the PoC

We provide a docker to avoid any compatibility issue. 

### Setup the environment 

First, build the docker:
```bash
sudo docker build --rm -t artifact_dragonstar .
```

You can then run the docker:
```bash
sudo docker run --mount type=bind,source="$(pwd)"/shared_folder,target=/home/poc_user/PoC/shared_folder --security-opt seccomp=./seccomp.json -it artifact_dragonstar
``` 

### Running experiments

Functional test by comparing outputs with OpenSSL's:
```
./scripts/differential_testing.sh
```

Benchmark our implementation against OpenSSL (as deployed on the system) and OpenSSL without assembly.
Since our benchmark relies on the `perf` tool, you may need to enable it on your host system with 
```
echo 0 | sudo tee /proc/sys/kernel/perf_event_paranoid
```
Then you can run the following in the docker container:

```bash
./scripts/perf_evaluation/bench.sh
```

This command will run the benchmark on 20 different passwords, repeating the handshake 1000 times for each password. It produce various PDF comparing the performance of each library with different metrics (cycles, time, instruction).