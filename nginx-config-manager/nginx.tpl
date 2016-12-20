# If we receive X-Forwarded-Proto, pass it through; otherwise, pass along the
# scheme used to connect to this server
map $http_x_forwarded_proto $proxy_x_forwarded_proto {
  default $http_x_forwarded_proto;
  ''      $scheme;
}

# If we receive X-Forwarded-Port, pass it through; otherwise, pass along the
# server port the client connected to
map $http_x_forwarded_port $proxy_x_forwarded_port {
  default $http_x_forwarded_port;
  ''      $server_port;
}

# If we receive Upgrade, set Connection to "upgrade"; otherwise, delete any
# Connection header that may have been passed to this server
map $http_upgrade $proxy_connection {
  default upgrade;
  '' close;
}

gzip_types text/plain text/css application/javascript application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript;

log_format vhost '$host $remote_addr - $remote_user [$time_local] '
                 '"$request" $status $body_bytes_sent '
                 '"$http_referer" "$http_user_agent"';

access_log off;

# HTTP 1.1 support
proxy_http_version 1.1;
proxy_buffering off;
proxy_set_header Host $http_host;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection $proxy_connection;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $proxy_x_forwarded_proto;
proxy_set_header X-Forwarded-Port $proxy_x_forwarded_port;

# Mitigate httpoxy attack (see README for details)
proxy_set_header Proxy "";

##########################################
## Catch-all Server
##########################################

server {
	server_name _ default_server;
	listen 80;
	access_log /var/log/nginx/access.log vhost;
	return 503; # Is there a better error code?  404?
}

{{/*
server {
  server_name _ default_server;
  listen 443;
	access_log /var/log/nginx/access.log vhost;
  return 301 http://$host$request_uri;
}
*/}}

{{/* Get the current container.  We use this filter out containers on different networks. */}}
{{ $CurrentContainer := where $ "ID" .Docker.CurrentContainerID | first }}

{{/* Define template for server directive. */}}
{{ define "upstream" }}
	{{ if and .Address .Network }}
	server {{ .Network.IP }}:{{ .Address.Port }};
	{{ else if .Network }}
	server {{ .Network.IP }} down;
	{{ end }}
{{ end }}

{{/* Common body for server directive */}}
{{ define "server" }}

  {{/* Allow configuration of each host via includes */}}
  {{ if (exists (printf "/etc/nginx/vhost.d/%s" .Host)) }}
  include {{ printf "/etc/nginx/vhost.d/%s" .Host }};
  {{ else if (exists "/etc/nginx/vhost.d/default") }}
  include /etc/nginx/vhost.d/default;
  {{ end }}

  {{/* Respond to letsencrypt challenges */}}
  location /.well-known/acme-challenge {
    default_type  "text/plain";
    root          /tmp/letsencrypt-auto;
  }

  location / {
    {{ if eq .Proto "uwsgi" }}
    include uwsgi_params;
    uwsgi_pass {{ .Proto }}://{{ .Host }};
    {{ else }}
    proxy_pass {{ .Proto }}://{{ .Host }};
    {{ end }}

    {{ if (exists (printf "/etc/nginx/htpasswd/%s" .Host)) }}
    auth_basic	"Restricted {{ .Host }}";
    auth_basic_user_file	{{ (printf "/etc/nginx/htpasswd/%s" .Host) }};
    {{ end }}
  }

{{ end }}


{{/*
  Group containers by VIRTUAL_HOST.
  This allows a single container to serve multiple hosts.
  It also allows multiple containers to serve the same host. */}}
{{ range $host, $containers := groupByMulti $ "Env.VIRTUAL_HOST" "," }}

##########################################
## {{ $host }}
##########################################

upstream {{ $host }} {
  {{ range $container := where $containers "State.Running" true }}

    {{/* Only deal with containers sharing a network with the current */}}
    {{ range $knownNetwork := $CurrentContainer.Networks }}
    {{ range $containerNetwork := $container.Networks }}
    {{ if eq $knownNetwork.Name $containerNetwork.Name }}

      {{/* If only 1 port exposed, use that */}}
			{{ if eq (len $container.Addresses) 1 }}
        {{ $address := index $container.Addresses 0 }}
        {{ template "upstream" (dict "Container" $container "Address" $address "Network" $containerNetwork) }}
			{{/* If more than one port exposed, use the one matching VIRTUAL_PORT env var, falling back to standard web port 80 */}}
			{{ else }}
				{{ $port := coalesce $container.Env.VIRTUAL_PORT "80" }}
				{{ $address := where $container.Addresses "Port" $port | first }}
				{{ template "upstream" (dict "Container" $container "Address" $address "Network" $containerNetwork) }}
			{{ end }}

    {{ end }}
    {{ end }}
    {{ end }}
  {{ end }}
}


{{/* Get the VIRTUAL_PROTO defined by containers w/ the same vhost, falling back to "http" */}}
{{ $proto := or (first (groupByKeys $containers "Env.VIRTUAL_PROTO")) "http" }}

{{/* Get the best certificate name for the host */}}
{{ $certName := (first (groupByKeys $containers "Env.CERT_NAME")) }}
{{ $vhostCert := (closest (dir "/etc/nginx/certs") (printf "%s.crt" $host))}}
{{ $vhostCert := trimSuffix ".crt" $vhostCert }}
{{ $vhostCert := trimSuffix ".key" $vhostCert }}
{{ $cert := (coalesce $certName $vhostCert) }}

{{/* Determine whether the host is capable of HTTPS connections */}}
{{ $certPath := printf "/etc/nginx/certs/%s.crt" $cert }}
{{ $keyPath  := printf "/etc/nginx/certs/%s.key" $cert }}
{{ $dhPath   := printf "/etc/nginx/certs/%s.dhparam.pem" $cert }}
{{ $is_https := (and (ne $cert "") (exists $certPath) (exists $keyPath)) }}


{{/* Rules for HTTPS capable host */}}
{{ if $is_https }}

server {
	server_name {{ $host }};
	listen 80;
	access_log /var/log/nginx/access.log vhost;
	return 301 https://$host$request_uri;
}

server {
	server_name {{ $host }};
	listen 443 ssl http2;
	access_log /var/log/nginx/access.log vhost;

	ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
	ssl_ciphers 'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA:!DSS';

	ssl_prefer_server_ciphers on;
	ssl_session_timeout 5m;
	ssl_session_cache shared:SSL:50m;
	ssl_session_tickets off;

  ssl_certificate {{ $certPath }};
	ssl_certificate_key {{ $keyPath }};

	{{ if (exists $dhPath) }}
	ssl_dhparam {{ $dhPath }};
	{{ end }}

  {{ template "server" (dict "Proto" (trim $proto) "Host" (trim $host)) }}
}

{{/* Rules for non-HTTPS hosts */}}
{{ else }}

server {
	server_name {{ $host }};
	listen 80;
	access_log /var/log/nginx/access.log vhost;

  {{ template "server" (dict "Proto" (trim $proto) "Host" (trim $host)) }}
}

{{/*
server {
	server_name {{ $host }};
	listen 443;
	access_log /var/log/nginx/access.log vhost;
	return 301 http://$host$request_uri;
}
*/}}

{{ end }}
{{ end }}
