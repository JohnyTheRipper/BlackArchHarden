#!/bin/bash

# Update and upgrade system packages
apt update && apt upgrade -y

# Install essential hardening and security tools
apt install -y lynis chkrootkit rkhunter fail2ban denyhosts clamav apparmor-utils unattended-upgrades knockd ufw ossec-hids-server

# --- SECURITY AUDIT ---
# Run a comprehensive security audit using Lynis
lynis audit system

# --- SSH HARDENING ---
# Disable root login from remote connections, only allow localhost
sed -i '/^PermitRootLogin/s/.*/PermitRootLogin no/' /etc/ssh/sshd_config

# Change SSH default port to 2200 and disable password authentication
sed -i '/^#Port/s/.*/Port 2200/' /etc/ssh/sshd_config
sed -i '/^#PasswordAuthentication/s/.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart ssh

# --- PASSWORD POLICY ---
# Set strong password requirements in pwquality.conf
sed -i '/minlen/s/#*//; /minlen/s/=.*/=16/' /etc/security/pwquality.conf
sed -i '/dcredit/s/#*//; /dcredit/s/=.*/=-2/' /etc/security/pwquality.conf
sed -i '/ucredit/s/#*//; /ucredit/s/=.*/=-2/' /etc/security/pwquality.conf
sed -i '/ocredit/s/#*//; /ocredit/s/=.*/=-2/' /etc/security/pwquality.conf
sed -i '/lcredit/s/#*//; /lcredit/s/=.*/=-2/' /etc/security/pwquality.conf

# Set password expiration and warning policies
sed -i '/^PASS_MAX_DAYS/s/.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i '/^PASS_MIN_DAYS/s/.*/PASS_MIN_DAYS   1/' /etc/login.defs
sed -i '/^PASS_WARN_AGE/s/.*/PASS_WARN_AGE   7/' /etc/login.defs

# --- DISABLE UNNECESSARY SERVICES ---
# Disable services that are not needed for server operation
systemctl disable bluetooth
systemctl disable avahi-daemon
systemctl disable cups
systemctl disable lightdm
systemctl disable NetworkManager

# --- FIREWALL SETUP (UFW) ---
# Deny all incoming traffic and allow all outgoing traffic
ufw default deny incoming
ufw default allow outgoing

# Allow SSH on the custom port 2200
ufw allow 2200/tcp
ufw enable

# --- FAIL2BAN SETUP ---
# Configure fail2ban to protect SSH against brute-force attacks
cat <<EOT > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 86400
maxretry = 5

[sshd]
enabled = true
port = 2200
EOT

# Restart fail2ban to apply the changes
systemctl restart fail2ban

# --- PORT KNOCKING SETUP ---
# Configure port knocking to further secure SSH access
cat <<EOT > /etc/knockd.conf
[options]
    UseSyslog

[opencloseSSH]
    sequence    = 5000,6000,7000
    seq_timeout = 15
    command     = /sbin/iptables -A INPUT -s %IP% -p tcp --dport 2200 -j ACCEPT
    tcpflags    = syn
EOT

# Start knockd service for port knocking
systemctl enable knockd
systemctl start knockd

# --- INTRUSION DETECTION (OSSEC) ---
# Install and configure OSSEC for real-time intrusion detection
/var/ossec/bin/ossec-control start

# --- VIRUS SCANNING ---
# Update ClamAV virus definitions and run a full scan
freshclam
clamscan -r /

# --- SUDO HARDENING ---
# Harden sudo by reducing the timestamp and password timeouts
echo "Defaults timestamp_timeout=60,passwd_timeout=30" >> /etc/sudoers

# --- LOGGING CONFIGURATION ---
# Ensure secure logging for authentication events
echo "auth.* /var/log/auth.log" >> /etc/rsyslog.conf
echo "authpriv.* /var/log/auth.log" >> /etc/rsyslog.conf
echo "authpriv.none /var/log/messages" >> /etc/rsyslog.conf
systemctl restart rsyslog

# --- AUTOMATIC SECURITY UPDATES ---
# Enable unattended-upgrades for automatic security updates
echo 'APT::Periodic::Update-Package-Lists "1";' >> /etc/apt/apt.conf.d/20auto-upgrades
echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/20auto-upgrades

# --- APPARMOR ENABLED ---
# Ensure AppArmor is enabled for enhanced security
systemctl enable apparmor
systemctl start apparmor

# --- KERNEL SECURITY (SYSCTL) ---
# Apply sysctl security hardening
cat <<SYSCTL_CONF > /etc/sysctl.d/99-security-hardening.conf
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable IPv6 if not in use
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
SYSCTL_CONF

# Apply sysctl settings immediately
sysctl --system

# --- DEAD MAN'S SWITCH ---
# Set up a dead man's switch to ensure the system is updated
touch /tmp/dead_mans_switch
trap 'touch /tmp/dead_mans_switch' EXIT

# Reset the switch every 12 hours (set it in the background)
(sleep 43200 && touch /tmp/dead_mans_switch) &

# Remove the dead man's switch at the end of the script
rm -f /tmp/dead_mans_switch

# --- FINAL UPDATES ---
# Ensure all packages are up to date
apt-get install -y --only-upgrade $(apt list --upgradable 2>/dev/null | grep -oP '^\S+' | grep -vE '(Listing|apt-list|done|Reading)')

# Reboot to apply all changes
reboot
