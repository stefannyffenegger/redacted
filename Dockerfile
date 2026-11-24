# Static container for the redaction tool. All processing still happens in the browser:
# the server only hands out the HTML/CSS/JS and never sees any document or mapping.
#
#   docker build -t redacted .
#   docker run --rm -p 8080:8080 redacted      # then open http://localhost:8080
FROM docker.io/nginxinc/nginx-unprivileged:1.27-alpine

COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY index.html /usr/share/nginx/html/
COPY css/ /usr/share/nginx/html/css/
COPY js/ /usr/share/nginx/html/js/
COPY samples/ /usr/share/nginx/html/samples/

EXPOSE 8080
USER 101
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO /dev/null http://127.0.0.1:8080/ || exit 1
