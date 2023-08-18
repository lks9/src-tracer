FROM    alpine

RUN     apk add alpine-sdk
ARG     USERNAME=src_tracer_user
ARG     PASSWORD=123456
# add user and config doas so that user can access to root through doas
RUN     apk add doas; \
        adduser -g "$USERNAME" -D $USERNAME; \
        echo "$USERNAME:$PASSWORD" | chpasswd; \
        adduser $USERNAME wheel;\
        echo 'permit persist :wheel' >> /etc/doas.d/doas.conf; \
        echo 'permit nopass :wheel as root' >> /etc/doas.d/doas.conf

# add python3, pip and use pip to install libclang
RUN     apk add python3 py3-pip; \
        pip install libclang

# add user to abuild group
RUN     addgroup $USERNAME abuild

# change to user
USER    $USERNAME
WORKDIR /home/$USERNAME

# clone src-tracer and aports
RUN     git clone https://gitlab.alpinelinux.org/alpine/aports.git; \
        git clone https://github.com/lks9/src-tracer.git

# setup for src-tracer
RUN     cd src-tracer/ && make

RUN     abuild-keygen -a -i -n


CMD ["/bin/sh"]

