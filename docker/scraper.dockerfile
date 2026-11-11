# SeleniumBase scraper (Ubuntu base) with the emSign ECC Root CA - G3 removal (DEC-19).
FROM jez500/seleniumbase-scrapper@sha256:501895ba8e1f592b0480c870d10113b94f1a2ba3185dfaf89b41b9e36fe8f25f

COPY ca/emsign-g3.sh /usr/local/sbin/emsign-g3.sh
RUN sh /usr/local/sbin/emsign-g3.sh remove && rm -f /usr/local/sbin/emsign-g3.sh
