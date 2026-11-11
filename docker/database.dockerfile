# MySQL 8.2 (Oracle Linux base) with the emSign ECC Root CA - G3 removal (DEC-19).
FROM mysql@sha256:212fe73edca5df6ff14826d5eb975c914bfb91f82a2e923f9050568f99525da1

COPY ca/emsign-g3.sh /usr/local/sbin/emsign-g3.sh
RUN microdnf install -y ca-certificates openssl \
    && sh /usr/local/sbin/emsign-g3.sh remove \
    && rm -f /usr/local/sbin/emsign-g3.sh \
    && microdnf clean all
