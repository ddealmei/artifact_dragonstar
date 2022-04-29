FROM ubuntu:20.04

RUN apt update && \
	DEBIAN_FRONTEND="noninteractive" \
	apt install -y gcc make wget vim python3 python3-pip libssl-dev

# Install PoC material (spy, parser, dictionary reducer)
COPY ./ /root/PoC/
WORKDIR /root/PoC/
RUN make libevercrypt.so
RUN make bin/sae_dragonstar bin/sae_dragonfly
