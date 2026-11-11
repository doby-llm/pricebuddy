# MySQL 8.2 (Oracle Linux base) with the emSign ECC Root CA - G3 removal (DEC-19).
FROM mysql@sha256:212fe73edca5df6ff14826d5eb975c914bfb91f82a2e923f9050568f99525da1

# p11-kit distrusts whatever is in source/blacklist. Without this entry, the update-ca-trust run
# inside emsign-g3.sh regenerates the G3 bundle from /usr/share/pki/ca-trust-source.
COPY ca/emsign-g3-blacklist.pem /etc/pki/ca-trust/source/blacklist/emsign-g3.pem
COPY ca/emsign-g3.sh /usr/local/sbin/emsign-g3.sh
RUN microdnf install -y ca-certificates openssl \
    && sh /usr/local/sbin/emsign-g3.sh remove \
    && rm -f /usr/local/sbin/emsign-g3.sh \
    && microdnf clean all
