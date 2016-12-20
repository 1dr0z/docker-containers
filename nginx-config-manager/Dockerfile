FROM ubuntu:xenial

RUN apt-get update \
 && apt-get install -y --no-install-recommends supervisor letsencrypt \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /etc/nginx/certs /etc/nginx/conf.d

COPY docker-gen /usr/local/bin/docker-gen
COPY generate-config /usr/local/bin/generate-config
COPY generate-certificate /usr/local/bin/generate-certificate

COPY nginx.tpl /nginx.tpl
COPY supervisord.conf /supervisord.conf

VOLUME /etc/nginx/

CMD ["/usr/bin/supervisord", "-c", "supervisord.conf"]
