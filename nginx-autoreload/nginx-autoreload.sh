#!/bin/sh

/usr/sbin/nginx "$@"

inotifywait -e modify,move,create,delete -mr /etc/nginx/ | while read file event tm; do
	/usr/sbin/nginx -s reload
done
