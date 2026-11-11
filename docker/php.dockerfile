ARG PHP_VERSION=8.4

# Build vendor, required for build frontend
FROM jez500/pricebuddy-tests-8.4@sha256:78470f6281f557e87e00cb06f9f36c618a8fdec7a673fd9737b4c8e656f88db7 AS builder

COPY ../.. /app

RUN mkdir -p storage/framework/sessions \
    && mkdir -p storage/framework/views \
    && mkdir -p storage/framework/testing \
    && mkdir -p storage/logs \
    && mkdir -p storage/app/public

RUN composer install --no-dev

RUN npm install && \
    npm run build && \
    cd docs && \
    npm install && \
    npm run docs:build

FROM jez500/pricebuddy-base-8.4@sha256:46769301498709a6272b904ee894d51f1e1ec0730465482482de2f3203f9bedd

ARG APP_VERSION=development
ENV APP_VERSION=${APP_VERSION}

COPY ../.. /app
COPY --from=builder /app/vendor /app/vendor
COPY --from=builder /app/public/build /app/public/build
COPY --from=builder /app/docs/docs/.vuepress/dist /app/public/docs

# Upgrade inherited OS packages on every published build so each release ships
# current Debian security point-releases, independent of when the base image
# was last rebuilt (mitigates CVEs reported against the published image).
RUN apt-get update && apt-get upgrade -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY ../../docker/php/php.ini /usr/local/etc/php/conf.d/zzz-php-overrides.ini
COPY ../../docker/php/schedule-cron /etc/cron.d/schedule-cron
COPY ../../docker/php/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY ../../docker/php/start-app.sh /start-app.sh
COPY ../../docker/php/start-cron.sh /start-cron.sh

RUN rm -rf /var/www/html \
    && ln -s /app/public /var/www/html \
    && a2enmod rewrite \
    && chmod 0644 /etc/cron.d/schedule-cron \
    && chmod +x /start-app.sh \
    && chmod +x /start-cron.sh \
    && touch /var/log/cron.log \
    && mkdir -p storage/framework/sessions \
    && mkdir -p storage/framework/views \
    && mkdir -p storage/framework/testing \
    && mkdir -p storage/logs \
    && mkdir -p storage/app/public

RUN composer install --no-dev

# emSign ECC Root CA - G3 removal (DEC-19). Install ca-certificates and openssl in the same RUN.
COPY ca/emsign-g3.sh /usr/local/sbin/emsign-g3.sh
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates openssl \
    && sh /usr/local/sbin/emsign-g3.sh remove \
    && rm -f /usr/local/sbin/emsign-g3.sh \
    && rm -rf /var/lib/apt/lists/*

CMD ["/start-app.sh"]
