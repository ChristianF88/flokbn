FROM nginx:stable-alpine

RUN apk add --no-cache dumb-init

# Copy custom Nginx config into the container
COPY default.conf /etc/nginx/conf.d/default.conf

# Empty deny include so nginx starts before the banpoller's first write
RUN mkdir -p /etc/nginx/banned && touch /etc/nginx/banned/deny.conf

# Static body for / (see default.conf: deny needs the access phase)
RUN printf 'ok' > /usr/share/nginx/html/index.html

# Entrypoint launches the banpoller (when BANLIST_URL is set) and nginx
COPY entrypoint.sh /entrypoint.sh
COPY banpoller.sh /banpoller.sh
RUN chmod +x /entrypoint.sh /banpoller.sh

# Expose HTTP port
EXPOSE 80

# Use dumb-init as PID 1 and run our entrypoint
ENTRYPOINT ["/usr/bin/dumb-init", "--", "/entrypoint.sh"]
