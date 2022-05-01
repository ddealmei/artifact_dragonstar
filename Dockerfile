FROM ubuntu:20.04

RUN apt update && \
	DEBIAN_FRONTEND="noninteractive" \
	apt install -y clang make vim python3 python3-pip python3-matplotlib python3-numpy libssl-dev linux-tools-$(uname -r) linux-cloud-tools-$(uname -r) sudo python

# Create a user with access to sudo to avoid ACL conflicts in shared_folder
ARG user=poc_user
ARG group=poc_user
ARG uid=1000
ARG gid=1000
RUN groupadd -g ${gid} ${group}
RUN useradd -u ${uid} -g ${group} -s /bin/bash -m ${user} -p poc_user
RUN echo "${user} ALL=(ALL:ALL) NOPASSWD: ALL" > /etc/sudoers

COPY ./ /home/${user}/PoC/
WORKDIR /home/${user}/PoC/
RUN chown -R ${user}:${group} /home/${user}/PoC

USER ${uid}:${gid}

RUN ln -s /home/${user}/PoC/haclstar/kremlin/include/kremlin /home/${user}/PoC/haclstar/gcc-compatible/kremlin
RUN make -j