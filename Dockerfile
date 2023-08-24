FROM    alpine

# install dependency for angr
RUN     apk add --no-cache alpine-sdk python3 py3-pip python3-dev linux-headers bash

# arg to setup user
ARG     USERNAME=src_tracer_user
ARG     PASSWORD=123456
# add user and config doas so that user can access to root through doas
RUN     apk add doas; \
        adduser -g "$USERNAME" -D $USERNAME; \
        echo "$USERNAME:$PASSWORD" | chpasswd; \
        adduser $USERNAME wheel;\
        echo 'permit persist :wheel' >> /etc/doas.d/doas.conf; \
        echo 'permit nopass :wheel as root' >> /etc/doas.d/doas.conf

# add user to abuild group
RUN     addgroup $USERNAME abuild

# change to user
USER    $USERNAME
WORKDIR /home/$USERNAME

# create a python virtual enviroment for angr
RUN     python3 -m venv /home/$USERNAME/angr-venv

# install angr dependency
RUN     source /home/$USERNAME/angr-venv/bin/activate && pip install archinfo
RUN     source /home/$USERNAME/angr-venv/bin/activate && pip install pyvex
RUN     source /home/$USERNAME/angr-venv/bin/activate && pip install cle
RUN     source /home/$USERNAME/angr-venv/bin/activate && pip install claripy
RUN     source /home/$USERNAME/angr-venv/bin/activate && pip install ailment
# install libclang for src-tracer
RUN     source /home/$USERNAME/angr-venv/bin/activate && pip install libclang

# clone angr and install without unicorn
RUN     git clone --depth 1 --branch v9.2.65 https://github.com/angr/angr.git
RUN     cd angr && \
        sed -i 's/, "unicorn==2\.0\.1\.post1"//g' pyproject.toml && \
        sed -i '/unicorn==2\.0\.1\.post1/d' setup.cfg && \
        sed -i '/self\.execute(_build_native/d' setup.py
RUN     source /home/$USERNAME/angr-venv/bin/activate && cd angr && pip install .

# clone src-tracer and aports
RUN     git clone https://gitlab.alpinelinux.org/alpine/aports.git; \
        git clone https://github.com/lks9/src-tracer.git

# setup for src-tracer
RUN     cd src-tracer/ && make

RUN     abuild-keygen -a -i -n


CMD     source /home/src_tracer_user/angr-venv/bin/activate && /bin/sh

