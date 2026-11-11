#!/bin/sh
# emSign ECC Root CA - G3 removal (SPEC DEC-19, CA incident). Usage: sh emsign-g3.sh remove|check
#   remove: drops the G3 certificate from every trust file below, then rebuilds the bundles.
#   check:  prints each path that still holds G3 and exits 1 when there is any.
# Matches the exact SHA-256 fingerprint of the certificate, never its name.
set -eu

MODE="${1:?usage: emsign-g3.sh remove|check}"
case "$MODE" in remove | check) ;; *) echo "unknown mode: $MODE" >&2; exit 2 ;; esac
G3="86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B"
command -v openssl >/dev/null 2>&1 || { echo "emsign-g3: openssl is required" >&2; exit 2; }
DEBIAN_SRC=/usr/share/ca-certificates
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FOUND=0
REMOVED=0

# SHA-256 fingerprint of the first certificate in $1 (the value part only).
fingerprint() {
  openssl x509 -noout -fingerprint -sha256 -in "$1" 2>/dev/null | sed 's/^[^=]*=//' || true
}

# Every certificate block in bundle or single-cert file $1: G3 blocks are reported (check)
# or dropped (remove). A file that holds only G3 is deleted.
bundle() {
  f="$1"; total=0; hit=0
  rm -rf "$WORK/split"; mkdir "$WORK/split"; : > "$WORK/keep.pem"
  awk -v d="$WORK/split" '/-----BEGIN CERTIFICATE-----/{i++; o=d "/" i ".pem"} o{print > o} /-----END CERTIFICATE-----/{o=""}' "$f"
  for c in "$WORK/split"/*.pem; do
    [ -e "$c" ] || continue
    total=$((total + 1))
    if [ "$(fingerprint "$c")" = "$G3" ]; then hit=$((hit + 1)); else cat "$c" >> "$WORK/keep.pem"; fi
  done
  [ "$hit" -eq 0 ] && return 0
  FOUND=$((FOUND + hit))
  if [ "$MODE" = check ]; then echo "$f"; return 0; fi
  if [ "$hit" -eq "$total" ]; then rm -f "$f"; else cat "$WORK/keep.pem" > "$f"; fi
  REMOVED=$((REMOVED + hit))
  echo "removed $hit G3 certificate(s) from $f"
}

# Debian rebuilds /usr/share/ca-certificates from /etc/ca-certificates.conf: disable the entry.
disable_conf() {
  rel="${1#"$DEBIAN_SRC"/}"
  [ -f /etc/ca-certificates.conf ] || return 0
  awk -v r="$rel" '$0 == r { print "!" r; next } { print }' /etc/ca-certificates.conf > "$WORK/conf"
  cat "$WORK/conf" > /etc/ca-certificates.conf
}

# 1. Source anchors (Debian/Ubuntu, Alpine, RHEL-family).
for f in $(find "$DEBIAN_SRC" /usr/local/share/ca-certificates /etc/pki/ca-trust/source/anchors /usr/share/pki/ca-trust-source/anchors \
    -type f \( -name '*.crt' -o -name '*.pem' \) 2>/dev/null || true); do
  bundle "$f"
  if [ "$MODE" = remove ] && [ ! -e "$f" ]; then
    case "$f" in "$DEBIAN_SRC"/*) disable_conf "$f" ;; esac
  fi
done

# 2. Hashed and per-certificate links in the system store (dangling links left by step 1 go too).
for f in $(find /etc/ssl/certs /etc/pki/tls/certs -maxdepth 1 \( -type f -o -type l \) 2>/dev/null || true); do
  if [ -L "$f" ] && [ ! -e "$f" ]; then
    [ "$MODE" = remove ] && rm -f "$f"
    continue
  fi
  if [ -L "$f" ]; then
    if [ "$(fingerprint "$f")" = "$G3" ]; then
      FOUND=$((FOUND + 1))
      if [ "$MODE" = check ]; then echo "$f"; else rm -f "$f"; REMOVED=$((REMOVED + 1)); echo "removed G3 link $f"; fi
    fi
    continue
  fi
  bundle "$f"
done

# 3. Bundles that are not under /etc/ssl/certs (symlinks are skipped: their target is handled above).
CERTIFI="$(find / -path /proc -prune -o -path /sys -prune -o -name cacert.pem -path '*certifi*' -print 2>/dev/null || true)"
for f in /etc/ssl/cert.pem /etc/pki/tls/cert.pem /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem $CERTIFI; do
  if [ -f "$f" ] && [ ! -L "$f" ]; then bundle "$f"; fi
done

# 4. Rebuild the bundles from the cleaned sources so that no G3 copy is regenerated.
if [ "$MODE" = remove ] && [ "$REMOVED" -gt 0 ]; then
  if command -v update-ca-certificates >/dev/null 2>&1; then
    if ! update-ca-certificates --fresh; then update-ca-certificates; fi
  fi
  if command -v update-ca-trust >/dev/null 2>&1; then update-ca-trust extract; fi
fi

echo "emsign-g3 $MODE: found=$FOUND removed=$REMOVED"
if [ "$MODE" = check ] && [ "$FOUND" -gt 0 ]; then exit 1; fi
exit 0
