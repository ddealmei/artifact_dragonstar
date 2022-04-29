# Dragonstar: A plugin verified cryptographic implementation for Dragonfly

The PAKE Dragonfly is used as SAE(-PT) in WPA3 authentication. 

TODO: add a speech and link to hacl


## Repository layout

TODO tldr: everythign is automated, just setup the docker and use the scripts under scripts/

## Run the PoC

We provide a docker to avoid any compatibility issue. 

### Setup the environment 

First, build the docker:
```bash
sudo docker build --rm -t artifact_dragonstar .
```

You can then run the docker:
```bash
sudo docker run -it artifact_dragonstar
``` 

### Running experiments

Functional testing by comparing outputs with OpenSSL's:
```
./scripts/differential_testing.sh
```

TODO: add benchmarking scripts