FROM ubuntu:xenial

RUN echo "deb http://ppa.launchpad.net/ansible/ansible/ubuntu xenial main" | tee /etc/apt/sources.list.d/ansible.list \
 && echo "deb-src http://ppa.launchpad.net/ansible/ansible/ubuntu xenial main" | tee -a /etc/apt/sources.list.d/ansible.list \
 && apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 7BB9C367 \
 && apt-get update \
 && apt-get install -y --no-install-recommends ansible \
 && rm -rf /var/lib/apt/lists/* \
 && echo 'localhost' > /etc/ansible/hosts

ONBUILD RUN apt-get install -y openssl ca-certificates

CMD ["ansible", "-c local", "-m setup", "all"]
