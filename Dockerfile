FROM ubuntu:20.04

RUN apt update && \
	DEBIAN_FRONTEND="noninteractive" \
	apt install -y clang make vim python3 python3-pip libssl-dev

COPY ./ /root/PoC/
WORKDIR /root/PoC/
RUN ln -s /root/PoC/haclstar/kremlin/include/kremlin /root/PoC/haclstar/gcc-compatible/kremlin
RUN make -j