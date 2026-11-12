#!/usr/bin/env bash
# Host firewall for the portal server (Ubuntu/Debian, UFW). Default deny; open only what is needed.
# Run as root on the SERVER (not on your laptop):  sudo bash deploy/firewall.sh
# Replace MGMT_NET with the network your administrators connect from (VPN / management VLAN).
set -euo pipefail

MGMT_NET="10.99.0.0/24"

ufw --force reset
ufw default deny incoming
ufw default allow outgoing

ufw allow 80/tcp  comment 'HTTP (redirects to HTTPS)'
ufw allow 443/tcp comment 'HTTPS'
ufw allow from "$MGMT_NET" to any port 22 proto tcp comment 'SSH from management network only'
ufw limit 22/tcp                                   # extra: rate-limit SSH connection attempts

# Gunicorn (8000) listens on 127.0.0.1 only, so it is never exposed. No rule is created for it on purpose.

ufw logging on
ufw --force enable
ufw status verbose
