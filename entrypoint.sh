#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
set -o xtrace

# Require environment variables.
if [[ -z "${SUBSPACE_HTTP_HOST-}" ]]; then
    echo "Environment variable SUBSPACE_HTTP_HOST required. Exiting."
    exit 1
fi

# Require environment variables.
if [[ -z "${SUBSPACE_WIREGUARD_PORT-}" ]]; then
    export SUBSPACE_WIREGUARD_PORT=51820
fi

# Require environment variables.
if [[ -z "${SUBSPACE_CLIENT_IPV6_ENABLED-}" ]]; then
    export SUBSPACE_CLIENT_IPV6_ENABLED=false
fi

# Require environment variables.
if [[ -z "${SUBSPACE_CLIENT_IPV6_SUBNET-}" && "${SUBSPACE_CLIENT_IPV6_ENABLED}" = true ]]; then
    echo "Environment variable SUBSPACE_CLIENT_IPV6_SUBNET required. Exiting."
    exit 1
fi

# Require environment variables.
if [[ -z "${SUBSPACE_CLIENT_IPV4_GATEWAY-}" && "${SUBSPACE_CLIENT_IPV6_ENABLED}" = true ]]; then
    echo "Environment variable SUBSPACE_CLIENT_IPV4_GATEWAY required. Exiting."
    exit 1
fi

# Require environment variables.
if [[ -z "${SUBSPACE_CLIENT_IPV6_GATEWAY-}" && "${SUBSPACE_CLIENT_IPV6_ENABLED}" = true ]]; then
    echo "Environment variable SUBSPACE_CLIENT_IPV6_GATEWAY required. Exiting."
    exit 1
fi

# Require environment variables.
if [[ -z "${SUBSPACE_CLIENT_IPV4_DNS-}" ]]; then
    export SUBSPACE_CLIENT_DNS=${SUBSPACE_CLIENT_IPV4_GATEWAY}
fi

# Require environment variables.
if [[ -z "${SUBSPACE_CLIENT_IPV6_DNS-}" ]]; then
    export SUBSPACE_CLIENT_DNS=${SUBSPACE_CLIENT_IPV6_GATEWAY}
fi

# Optional environment variables.
if [[ -z "${SUBSPACE_BACKLINK-}" ]]; then
    export SUBSPACE_BACKLINK=""
fi

if [[ -z "${SUBSPACE_LETSENCRYPT-}" ]]; then
    export SUBSPACE_LETSENCRYPT="true"
fi

if [[ -z "${SUBSPACE_HTTP_ADDR-}" ]]; then
    export SUBSPACE_HTTP_ADDR=":80"
fi

if [[ -z "${SUBSPACE_HTTP_INSECURE-}" ]]; then
    export SUBSPACE_HTTP_INSECURE="false"
fi

if [[ -z "${SUBSPACE_CLIENT_IPV4_USE_DNS-}" ]]; then
    export SUBSPACE_CLIENT_IPV4_USE_DNS=true
fi

if [[ -z "${SUBSPACE_CLIENT_IPV4_USE_GATEWAY-}" ]]; then
    export SUBSPACE_CLIENT_IPV4_USE_GATEWAY=true
fi

if [[ -z "${SUBSPACE_CLIENT_IPV6_USE_DNS-}" ]]; then
    export SUBSPACE_CLIENT_IPV6_USE_DNS=true
fi

if [[ -z "${SUBSPACE_CLIENT_IPV6_USE_GATEWAY-}" ]]; then
    export SUBSPACE_CLIENT_IPV6_USE_GATEWAY=true
fi

if [[ -z "${SUBSPACE_CLIENT_KEEP_ALIVE-}" ]]; then
    export SUBSPACE_CLIENT_KEEP_ALIVE=0
fi

export NAMESERVER="1.1.1.1"
export DEBIAN_FRONTEND="noninteractive"

# Set DNS server
echo "nameserver ${NAMESERVER}" >/etc/resolv.conf

# ipv4
if ! /sbin/iptables -t nat --check POSTROUTING -s "${SUBSPACE_CLIENT_IPV4_SUBNET}" -j MASQUERADE; then
    /sbin/iptables -t nat --append POSTROUTING -s "${SUBSPACE_CLIENT_IPV4_SUBNET}" -j MASQUERADE
fi

if ! /sbin/iptables --check FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT; then
    /sbin/iptables --append FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
fi

if ! /sbin/iptables --check FORWARD -s "${SUBSPACE_CLIENT_IPV4_SUBNET}" -j ACCEPT; then
    /sbin/iptables --append FORWARD -s "${SUBSPACE_CLIENT_IPV4_SUBNET}" -j ACCEPT
fi

if [[ "${SUBSPACE_CLIENT_IPV6_ENABLED}" = true ]]; then
    # ipv6
    if ! /sbin/ip6tables -t nat --check POSTROUTING -s "${SUBSPACE_CLIENT_IPV6_SUBNET}" -j MASQUERADE; then
        /sbin/ip6tables -t nat --append POSTROUTING -s "${SUBSPACE_CLIENT_IPV6_SUBNET}" -j MASQUERADE
    fi

    if ! /sbin/ip6tables --check FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT; then
        /sbin/ip6tables --append FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
    fi

    if ! /sbin/ip6tables --check FORWARD -s "${SUBSPACE_CLIENT_IPV6_SUBNET}" -j ACCEPT; then
        /sbin/ip6tables --append FORWARD -s "${SUBSPACE_CLIENT_IPV6_SUBNET}" -j ACCEPT
    fi
fi

# ipv4 - DNS Leak Protection
if ! /sbin/iptables -t nat --check OUTPUT -s "${SUBSPACE_CLIENT_IPV4_SUBNET}" -p udp --dport 53 -j DNAT --to "${SUBSPACE_CLIENT_IPV4_DNS}:53"; then
    /sbin/iptables -t nat --append OUTPUT -s "${SUBSPACE_CLIENT_IPV4_SUBNET}" -p udp --dport 53 -j DNAT --to "${SUBSPACE_CLIENT_IPV4_DNS}:53"
fi

if ! /sbin/iptables -t nat --check OUTPUT -s "${SUBSPACE_CLIENT_IPV4_SUBNET}" -p tcp --dport 53 -j DNAT --to "${SUBSPACE_CLIENT_IPV4_DNS}:53"; then
    /sbin/iptables -t nat --append OUTPUT -s "${SUBSPACE_CLIENT_IPV4_SUBNET}" -p tcp --dport 53 -j DNAT --to "${SUBSPACE_CLIENT_IPV4_DNS}:53"
fi

if [[ "${SUBSPACE_CLIENT_IPV6_ENABLED}" = true ]]; then
    # ipv6 - DNS Leak Protection
    if ! /sbin/ip6tables --wait -t nat --check OUTPUT -s "${SUBSPACE_CLIENT_IPV6_SUBNET}" -p udp --dport 53 -j DNAT --to "${SUBSPACE_CLIENT_IPV6_GATEWAY}"; then
        /sbin/ip6tables --wait -t nat --append OUTPUT -s "${SUBSPACE_CLIENT_IPV6_SUBNET}" -p udp --dport 53 -j DNAT --to "${SUBSPACE_CLIENT_IPV6_GATEWAY}"
    fi

    if ! /sbin/ip6tables --wait -t nat --check OUTPUT -s "${SUBSPACE_CLIENT_IPV6_SUBNET}" -p tcp --dport 53 -j DNAT --to "${SUBSPACE_CLIENT_IPV6_GATEWAY}"; then
        /sbin/ip6tables --wait -t nat --append OUTPUT -s "${SUBSPACE_CLIENT_IPV6_SUBNET}" -p tcp --dport 53 -j DNAT --to "${SUBSPACE_CLIENT_IPV6_GATEWAY}"
    fi

fi

# # Delete
# /sbin/iptables -t nat --delete OUTPUT -s 10.99.97.0/16 -p udp --dport 53 -j DNAT --to 10.99.97.1:53
# /sbin/iptables -t nat --delete OUTPUT -s 10.99.97.0/16 -p tcp --dport 53 -j DNAT --to 10.99.97.1:53
# /sbin/ip6tables --wait -t nat --delete OUTPUT -s fd00::10:97:0/112 -p udp --dport 53 -j DNAT --to fd00::10:97:1
# /sbin/ip6tables --wait -t nat --delete OUTPUT -s fd00::10:97:0/112 -p tcp --dport 53 -j DNAT --to fd00::10:97:1
# /sbin/iptables -t nat --delete POSTROUTING -s 10.99.97.0/24 -j MASQUERADE
# /sbin/iptables --delete FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
# /sbin/iptables --delete FORWARD -s 10.99.97.0/24 -j ACCEPT
# /sbin/ip6tables -t nat --delete POSTROUTING -s fd00::10:97:0/112 -j MASQUERADE
# /sbin/ip6tables --delete FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
# /sbin/ip6tables --delete FORWARD -s fd00::10:97:0/112 -j ACCEPT

#
# WireGuard (10.99.97.0/24)
#
if ! test -d /data/wireguard; then
    mkdir /data/wireguard
    cd /data/wireguard

    mkdir clients
    touch clients/null.conf # So you can cat *.conf safely
    mkdir peers
    touch peers/null.conf # So you can cat *.conf safely

    # Generate public/private server keys.
    wg genkey | tee server.private | wg pubkey > server.public
fi

cat <<WGSERVER >/data/wireguard/server.conf
[Interface]
PrivateKey = $(cat /data/wireguard/server.private)
ListenPort = ${SUBSPACE_WIREGUARD_PORT}

WGSERVER
cat /data/wireguard/peers/*.conf >>/data/wireguard/server.conf

if ip link show wg0 2>/dev/null; then
    ip link del wg0
fi
ip link add wg0 type wireguard
ip addr add "${SUBSPACE_CLIENT_IPV4_GATEWAY}"/24 dev wg0
if [[ "${SUBSPACE_CLIENT_IPV6_ENABLED}" = true ]]; then
    ip addr add "${SUBSPACE_CLIENT_IPV6_GATEWAY}"/112 dev wg0
fi
wg setconf wg0 /data/wireguard/server.conf
ip link set wg0 up

# dnsmasq service
if ! test -d /etc/sv/dnsmasq; then
    if [[ "${SUBSPACE_CLIENT_IPV6_ENABLED}" = true ]]; then
    cat <<DNSMASQ >/etc/dnsmasq.conf
    # Only listen on necessary addresses.
    listen-address=127.0.0.1,${SUBSPACE_CLIENT_IPV4_GATEWAY},${SUBSPACE_CLIENT_IPV6_GATEWAY}

    # Never forward plain names (without a dot or domain part)
    domain-needed

    # Never forward addresses in the non-routed address spaces.
    bogus-priv
DNSMASQ
    else
    cat <<DNSMASQ >/etc/dnsmasq.conf
    # Only listen on necessary addresses.
    listen-address=127.0.0.1,${SUBSPACE_CLIENT_IPV4_GATEWAY}

    # Never forward plain names (without a dot or domain part)
    domain-needed

    # Never forward addresses in the non-routed address spaces.
    bogus-priv
DNSMASQ
    fi
    mkdir /etc/sv/dnsmasq
    cat <<RUNIT >/etc/sv/dnsmasq/run
#!/bin/sh
exec /usr/sbin/dnsmasq --no-daemon
RUNIT
    chmod +x /etc/sv/dnsmasq/run

# dnsmasq service log
    mkdir /etc/sv/dnsmasq/log
    mkdir /etc/sv/dnsmasq/log/main
    cat <<RUNIT >/etc/sv/dnsmasq/log/run
#!/bin/sh
exec svlogd -tt ./main
RUNIT
    chmod +x /etc/sv/dnsmasq/log/run
    ln -s /etc/sv/dnsmasq /etc/service/dnsmasq
fi

# subspace service
if ! test -d /etc/sv/subspace; then
    mkdir /etc/sv/subspace
    cat <<RUNIT >/etc/sv/subspace/run
#!/bin/sh
exec /app \
    "--http-host=${SUBSPACE_HTTP_HOST}" \
    "--http-addr=${SUBSPACE_HTTP_ADDR}" \
    "--http-insecure=${SUBSPACE_HTTP_INSECURE}" \
    "--backlink=${SUBSPACE_BACKLINK}" \
    "--letsencrypt=${SUBSPACE_LETSENCRYPT}" \
    "--wireguard-port=${SUBSPACE_WIREGUARD_PORT}" \
    "--client-ipv4-subnet=${SUBSPACE_CLIENT_IPV4_SUBNET}" \
    "--client-ipv4-gateway=${SUBSPACE_CLIENT_IPV4_GATEWAY}" \
    "--client-ipv4-use-gateway=${SUBSPACE_CLIENT_IPV4_USE_GATEWAY}" \
    "--client-ipv4-dns=${SUBSPACE_CLIENT_IPV4_DNS}" \
    "--client-ipv4-use-dns=${SUBSPACE_CLIENT_IPV4_USE_DNS}" \
    "--client-ipv6-enabled=${SUBSPACE_CLIENT_IPV6_ENABLED}" \
    "--client-ipv6-subnet=${SUBSPACE_CLIENT_IPV6_SUBNET}" \
    "--client-ipv6-gateway=${SUBSPACE_CLIENT_IPV6_GATEWAY}" \
    "--client-ipv6-use-gateway=${SUBSPACE_CLIENT_IPV6_USE_GATEWAY}" \
    "--client-ipv6-dns=${SUBSPACE_CLIENT_IPV6_DNS}" \
    "--client-ipv6-use-dns=${SUBSPACE_CLIENT_IPV6_USE_DNS}" \
    "--client-keep-alive=${SUBSPACE_CLIENT_KEEP_ALIVE}"
RUNIT
    chmod +x /etc/sv/subspace/run

    # subspace service log
    mkdir /etc/sv/subspace/log
    mkdir /etc/sv/subspace/log/main
    cat <<RUNIT >/etc/sv/subspace/log/run
#!/bin/sh
exec svlogd -tt ./main
RUNIT
    chmod +x /etc/sv/subspace/log/run
    ln -s /etc/sv/subspace /etc/service/subspace
fi

exec "$@"
