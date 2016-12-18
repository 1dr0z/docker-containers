FROM nginx:stable

RUN apt-get update \
 && apt-get install -y inotify-tools \
 && rm -rf /var/lib/apt/lists/*

COPY nginx-autoreload.sh /usr/local/bin/

CMD ["nginx-autoreload.sh"]
