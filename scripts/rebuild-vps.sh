#!/usr/bin/env bash
set -euo pipefail

LOG_PREFIX="[rebuild-vps]"

# =========================
# 基础日志与错误处理
# =========================
log() { echo "${LOG_PREFIX} $*"; }
warn() { echo "${LOG_PREFIX} WARN: $*" >&2; }
die() { echo "${LOG_PREFIX} ERROR: $*" >&2; exit 1; }

# =========================
# 基础工具与环境检测
# =========================
require_root() {
  # 必须以 root 执行，因为涉及系统配置、服务安装与用户 shell 变更
  if [[ "${EUID}" -ne 0 ]]; then
    die "This script must be run as root."
  fi
}

require_cmd() {
  # 检查命令是否存在
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    die "Missing required command: ${cmd}"
  fi
}

ensure_packages() {
  # 安装依赖包，保持非交互
  local packages=("$@")
  log "Installing packages: ${packages[*]}"
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
}

detect_debian_version() {
  # 仅支持 Debian 12/13
  if [[ ! -f /etc/os-release ]]; then
    die "Cannot detect OS version."
  fi
  # shellcheck disable=SC1091
  . /etc/os-release
  if [[ "${ID}" != "debian" ]]; then
    die "Unsupported OS: ${ID}. Only Debian 12/13 is supported."
  fi
  if [[ "${VERSION_ID}" != "12" && "${VERSION_ID}" != "13" ]]; then
    die "Unsupported Debian version: ${VERSION_ID}. Only Debian 12/13 is supported."
  fi
  log "Detected Debian ${VERSION_ID}."
}

backup_file() {
  # 备份配置文件，避免覆盖丢失
  local file="$1"
  if [[ -f "${file}" ]]; then
    cp -a "${file}" "${file}.bak.$(date +%Y%m%d%H%M%S)"
  fi
}

prompt_secret() {
  # 读取敏感信息（不会回显）
  local prompt="$1"
  local var
  read -r -s -p "${prompt}" var
  echo
  echo "${var}"
}

prompt_optional() {
  # 读取可选输入（允许回车跳过）
  local prompt="$1"
  local var
  read -r -p "${prompt}" var
  echo "${var}"
}

run_basic_checks() {
  require_root
  detect_debian_version
  # 基础命令检查
  require_cmd curl
  require_cmd git
  require_cmd tar
  require_cmd systemctl
  # 系统信息输出依赖
  ensure_packages iproute2 util-linux procps
  log "Basic checks passed."
}

configure_ssh() {
  require_root
  local sshd_config="/etc/ssh/sshd_config"
  backup_file "${sshd_config}"
  log "Updating SSH configuration."
  cat >"${sshd_config}" <<'EOF'
# Managed by rebuild-vps
Port 22222
Protocol 2
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
AllowTcpForwarding yes
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 5
MaxSessions 10
EOF

  if systemctl list-unit-files | grep -q '^ssh\.service'; then
    systemctl restart ssh
  else
    systemctl restart sshd
  fi
  log "SSH config updated. Port is 22222."
}

install_fail2ban() {
  require_root
  ensure_packages fail2ban
  local jail_local="/etc/fail2ban/jail.local"
  backup_file "${jail_local}"
  log "Writing fail2ban configuration."
  cat >"${jail_local}" <<'EOF'
#DEFAULT-START
[DEFAULT]
bantime = 600
findtime = 300
maxretry = 5
banaction = iptables-multiport
action = %(action_mwl)s
#DEFAULT-END

# 使用 systemd 日志（Debian 13 推荐）
backend = systemd
# 防止误封
usedns = no

# 忽略本机
ignoreip = 127.0.0.1/8 ::1

[sshd]
ignoreip = 127.0.0.1/8
enabled = true
filter = sshd
port = 22222
maxretry = 5
findtime = 300
bantime = 600
banaction = iptables-multiport
action = %(action_mwl)s
logpath = /var/log/auth.log

[sshd-aggressive]
enabled = true
port = 22222
filter = sshd-aggressive
logpath = /var/log/auth.log
maxretry = 2
findtime = 10m
bantime = 6h
EOF
  # 写入 jail.d 中的 sshd-aggressive.local
  mkdir -p /etc/fail2ban/jail.d
  cat >/etc/fail2ban/jail.d/sshd-aggressive.local <<'EOF'
[sshd-aggressive]
enabled = true
port = 22222
filter = sshd-aggressive
logpath = /var/log/auth.log
maxretry = 2
findtime = 10m
bantime = 6h
EOF
  # 写入 sshd-aggressive 过滤规则
  mkdir -p /etc/fail2ban/filter.d
  cat >/etc/fail2ban/filter.d/sshd-aggressive.conf <<'EOF'
[Definition]
allowipv6 = auto
failregex =
    ^.*Failed publickey for .* from <HOST> port \d+ ssh2
    ^.*Authentication failure for .* from <HOST>
    ^.*Invalid user .* from <HOST>
    ^.*User .* from <HOST> not allowed because not listed in AllowUsers

ignoreregex =
EOF
  systemctl enable --now fail2ban
  log "fail2ban installed and enabled."
}

apply_sysctl() {
  require_root
  local sysctl_conf="/etc/sysctl.d/99-custom.conf"
  backup_file "${sysctl_conf}"
  log "Writing sysctl configuration."
  cat >"${sysctl_conf}" <<'EOF'
########################################
# TCP 基础行为
########################################
net.ipv4.tcp_fin_timeout = 20
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_tw_buckets = 200000
net.ipv4.ip_local_port_range = 10240 65000

########################################
# 建连抗压 & SYN 防护
########################################
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_synack_retries = 5

########################################
# TCP 缓冲区（让内核自适应，别把内存打满）
########################################
net.ipv4.tcp_rmem = 4096 87380 8388608
net.ipv4.tcp_wmem = 4096 65536 8388608

########################################
# TCP 特性
########################################
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_congestion_control = bbr

########################################
# 网络队列 & socket
########################################
net.core.default_qdisc = fq
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 10000

net.core.rmem_default = 131072
net.core.wmem_default = 131072
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608

########################################
# IPv6（L7 代理一般不需要转发）
########################################
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0
net.ipv6.conf.eth0.accept_ra = 1
net.ipv6.conf.all.autoconf = 0
net.ipv6.conf.eth0.autoconf = 0
EOF
  sysctl --system
  log "sysctl applied."
}

install_gvm_go() {
  require_root
  # gvm 与 Go 编译依赖
  ensure_packages curl git bzip2 ca-certificates \
    gcc make bison gawk binutils libssl-dev libreadline-dev zlib1g-dev
  if [[ ! -f /etc/profile.d/gvm.sh ]]; then
    log "Installing gvm."
    bash -lc "curl -fsSL https://raw.githubusercontent.com/moovweb/gvm/master/binscripts/gvm-installer | bash"
    cat >/etc/profile.d/gvm.sh <<'EOF'
export GVM_ROOT="/root/.gvm"
if [ -s "${GVM_ROOT}/scripts/gvm" ]; then
  # shellcheck disable=SC1090
  . "${GVM_ROOT}/scripts/gvm"
fi
EOF
  fi
  log "Installing latest Go 1.25.x via gvm (preferred binary, fallback to source)."
  bash -lc '
    source /etc/profile.d/gvm.sh
    # gvm listall 输出可能包含空格与前缀，统一提取版本号再排序
    latest_125="$(gvm listall | tr -s " " "\n" | grep -E "^go1\.25\.[0-9]+$" | sort -V | tail -n 1)"
    if [[ -z "${latest_125}" ]]; then
      latest_125="go1.25.1"
    fi
    echo "[rebuild-vps] Selected Go version: ${latest_125}"
    # 先准备 bootstrap（gvm 编译新版本需要 go1.4）
    gvm install go1.4 -B || gvm install go1.4
    gvm use go1.4 --default
    # 优先二进制，失败再源码编译
    gvm install "${latest_125}" -B || gvm install "${latest_125}"
    gvm use "${latest_125}" --default
  '
}

install_caddy() {
  require_root
  ensure_packages curl git tar

  local xcaddy_version="0.4.5"
  if ! command -v xcaddy >/dev/null 2>&1; then
    log "Installing xcaddy ${xcaddy_version}."
    bash -lc "source /etc/profile.d/gvm.sh && go install github.com/caddyserver/xcaddy/cmd/xcaddy@v${xcaddy_version}"
    install -m 0755 "$(bash -lc 'source /etc/profile.d/gvm.sh && go env GOPATH')/bin/xcaddy" /usr/local/bin/xcaddy
  fi

  log "Building Caddy with custom modules."
  bash -lc '
    source /etc/profile.d/gvm.sh
    # 清理可能残留的 GOFLAGS（避免自动注入 -tags）
    unset GOFLAGS
    export GOFLAGS=
    xcaddy build v2.10.2 \
      --with github.com/mholt/caddy-l4 \
      --with github.com/libdns/libdns@master \
      --with github.com/mholt/caddy-webdav \
      --with github.com/caddy-dns/cloudflare \
      --with github.com/caddyserver/zerossl \
      --with github.com/porech/caddy-maxmind-geolocation \
      --with github.com/greenpau/caddy-security \
      --with github.com/caddyserver/cache-handler \
      --with github.com/BraveRoy/caddy-waf \
      --with github.com/caddyserver/forwardproxy=github.com/imgk/forwardproxy@udpinhttp \
      --with github.com/imgk/caddy-trojan \
      --with github.com/WeidiDeng/caddy-cloudflare-ip \
      --with github.com/mholt/caddy-events-exec \
      --with github.com/greenpau/caddy-security \
      --with github.com/mholt/caddy-ratelimit \
      --output /usr/local/bin/caddy
  '
  chmod 0755 /usr/local/bin/caddy

  if ! id -u caddy >/dev/null 2>&1; then
    useradd --system --home /var/lib/caddy --shell /usr/sbin/nologin caddy
  fi

  mkdir -p /etc/caddy /var/lib/caddy /var/log/caddy
  chown -R caddy:caddy /var/lib/caddy /var/log/caddy

  # 生成 Caddyfile：用户可交互输入信息，回车则使用占位符
  local caddyfile="/etc/caddy/Caddyfile"
  if [[ ! -f "${caddyfile}" ]]; then
    local cf_token
    local site_domain
    local admin_email
    local panel_port
    cf_token="$(prompt_secret 'Cloudflare API Token (will be saved in Caddyfile): ')"
    site_domain="$(prompt_optional 'Site domain (press Enter to use example.com): ')"
    admin_email="$(prompt_optional 'Admin email (press Enter to use admin@example.com): ')"
    panel_port="$(prompt_optional '1Panel port (press Enter to use 8888): ')"
    if [[ -z "${site_domain}" ]]; then
      site_domain="example.com"
    fi
    if [[ -z "${admin_email}" ]]; then
      admin_email="admin@example.com"
    fi
    if [[ -z "${panel_port}" ]]; then
      panel_port="8888"
    fi
    cat >"${caddyfile}" <<EOF
{
  email ${admin_email}
}

${site_domain} {
  tls {
    dns cloudflare ${cf_token}
  }
  reverse_proxy 127.0.0.1:${panel_port}
}
EOF
  fi

  cat >/etc/systemd/system/caddy.service <<'EOF'
[Unit]
Description=Caddy
After=network-online.target
Wants=network-online.target

[Service]
User=caddy
Group=caddy
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/caddy run --environ --config /etc/caddy/Caddyfile
ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile
TimeoutStopSec=5s
LimitNOFILE=1048576
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now caddy
  log "Caddy installed and started."
}

install_1panel() {
  require_root
  ensure_packages curl
  # 1Panel 安装需要交互式终端，否则会走默认值
  if [[ ! -t 0 ]]; then
    die "1Panel installer requires an interactive TTY. Please run this script in a terminal."
  fi

  local installed=0
  if [[ -x /usr/local/bin/1pctl ]] || [[ -d /opt/1panel ]]; then
    installed=1
  fi

  if [[ "${installed}" -eq 1 ]]; then
    log "Detected existing 1Panel installation."
    local choice
    read -r -p "1Panel 已安装，输入 s 跳过，输入 r 卸载后重装: " choice
    case "${choice}" in
      r|R)
        if [[ -x /usr/local/bin/1pctl ]]; then
          log "Uninstalling 1Panel via 1pctl (interactive)."
          /usr/local/bin/1pctl uninstall
        else
          warn "1pctl not found. Unable to uninstall automatically."
          read -r -p "继续尝试重新安装？输入 yes 继续，其它退出: " choice
          if [[ "${choice}" != "yes" && "${choice}" != "y" && "${choice}" != "Y" ]]; then
            die "User canceled."
          fi
        fi
        ;;
      s|S)
        log "Skipping 1Panel installation."
        return 0
        ;;
      *)
        die "Invalid choice."
        ;;
    esac
  fi

  log "Launching 1Panel official installer (interactive)."
  curl -fsSL https://resource.fit2cloud.com/1panel/package/v2/quick_start.sh -o /tmp/1panel_install.sh
  bash /tmp/1panel_install.sh </dev/tty
  log "1Panel installation completed. Keep track of the panel port from the installer."
}

install_sing_box() {
  require_root
  # 按官方 release tag 方式构建
  ensure_packages git make
  local version="v1.12.19"
  local workdir="/tmp/sing-box-build"
  local install_path="/usr/bin/sing-box"

  log "Building sing-box from ${version}."
  rm -rf "${workdir}"
  mkdir -p "${workdir}"
  cd "${workdir}"

  # 关闭 detached HEAD 提示（仅当前仓库生效）
  git -c advice.detachedHead=false clone --branch "${version}" --depth 1 https://github.com/SagerNet/sing-box.git
  cd "sing-box"

  # 使用官方 Makefile 参数，确保版本号写入二进制
  bash -lc "source /etc/profile.d/gvm.sh && make build \
    TAGS=\"with_quic,with_grpc,with_wireguard,with_utls,with_acme,with_gvisor\" \
    LDFLAGS=\"-X 'github.com/sagernet/sing-box/constant.Version=${version}' -X 'internal/godebug.defaultGODEBUG=multipathtcp=0' -s -w -buildid= -checklinkname=0\""

  local bin
  bin="$(find . -type f -name sing-box | head -n 1)"
  if [[ -z "${bin}" ]]; then
    die "sing-box build failed: binary not found."
  fi

  systemctl stop sing-box || true
  install -m 755 "${bin}" "${install_path}"
  "${install_path}" version || true
  systemctl start sing-box || true

  rm -rf "${workdir}"

  mkdir -p /usr/local/etc/sing-box
  local config="/usr/local/etc/sing-box/config.json"
  if [[ ! -f "${config}" ]]; then
    cat >"${config}" <<'EOF'
{
  "log": {
    "level": "info"
  },
  "inbounds": [
    {
      "type": "socks",
      "tag": "socks-in",
      "listen": "0.0.0.0",
      "listen_port": 1080
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
}
EOF
  fi

  cat >/etc/systemd/system/sing-box.service <<'EOF'
[Unit]
Description=sing-box
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/sing-box run -c /usr/local/etc/sing-box/config.json
Restart=on-failure
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now sing-box
  log "sing-box installed and started."
}

install_zsh_ohmyzsh() {
  require_root
  ensure_packages zsh git curl sudo

  local zsh_path
  zsh_path="$(command -v zsh)"
  if [[ -z "${zsh_path}" ]]; then
    die "zsh not found after installation."
  fi

  # 将默认 shell 统一切换为 zsh（包含 root 与所有本地用户）
  log "Setting default shell to zsh for all local users."
  while IFS=: read -r user _ uid _ _ home shell; do
    if [[ "${uid}" -ge 1000 && -d "${home}" ]]; then
      chsh -s "${zsh_path}" "${user}" || warn "Failed to change shell for ${user}"
    fi
  done </etc/passwd
  chsh -s "${zsh_path}" root || warn "Failed to change shell for root"

  # 为所有用户安装 oh-my-zsh 与插件（包含 root）
  log "Installing oh-my-zsh for users."
  local users=()
  while IFS=: read -r user _ uid _ _ home _; do
    if [[ "${uid}" -ge 0 && -d "${home}" ]]; then
      users+=("${user}:${home}")
    fi
  done </etc/passwd

  for entry in "${users[@]}"; do
    local user="${entry%%:*}"
    local home="${entry#*:}"
    if [[ ! -d "${home}" ]]; then
      continue
    fi
    if [[ ! -d "${home}/.oh-my-zsh" ]]; then
      log "Installing oh-my-zsh for ${user}."
      RUNZSH=no CHSH=no KEEP_ZSHRC=yes \
        sudo -u "${user}" -H bash -lc \
        "curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh | sh"
    fi

    # 尝试更新已有 zshrc 或创建最小可用配置
    if [[ -f "${home}/.zshrc" ]]; then
      if ! grep -q "zsh-syntax-highlighting" "${home}/.zshrc"; then
        sed -i "s/^plugins=.*/plugins=(git zsh-syntax-highlighting zsh-autosuggestions)/" "${home}/.zshrc" || true
      fi
    else
      cat >"${home}/.zshrc" <<'EOF'
export ZSH="$HOME/.oh-my-zsh"
ZSH_THEME="robbyrussell"
plugins=(git zsh-syntax-highlighting zsh-autosuggestions)
source $ZSH/oh-my-zsh.sh
EOF
      chown "${user}:${user}" "${home}/.zshrc" || true
    fi

    # 安装插件源码到 oh-my-zsh 的自定义目录
    local custom_dir="${home}/.oh-my-zsh/custom/plugins"
    mkdir -p "${custom_dir}"
    if [[ ! -d "${custom_dir}/zsh-syntax-highlighting" ]]; then
      git clone https://github.com/zsh-users/zsh-syntax-highlighting.git "${custom_dir}/zsh-syntax-highlighting"
    fi
    if [[ ! -d "${custom_dir}/zsh-autosuggestions" ]]; then
      git clone https://github.com/zsh-users/zsh-autosuggestions.git "${custom_dir}/zsh-autosuggestions"
    fi
    chown -R "${user}:${user}" "${home}/.oh-my-zsh" "${home}/.zshrc" || true
  done

  log "zsh + oh-my-zsh configured."
}

install_ufw() {
  require_root
  # 安装并配置 UFW，默认放行常用端口
  ensure_packages ufw

  log "Configuring UFW firewall."
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw allow 8433/tcp
  ufw allow 22222/tcp

  ufw --force enable
  ufw status verbose || true
  log "UFW configured and enabled."
}

summary() {
  log "Summary:"
  echo "  SSH port: 22222"
  echo "  Caddy config: /etc/caddy/Caddyfile"
  echo "  sing-box config: /usr/local/etc/sing-box/config.json"
  echo "  fail2ban config: /etc/fail2ban/jail.local"
  echo "  zsh: $(command -v zsh)"
  log "Service status:"
  systemctl --no-pager --full status caddy || true
  systemctl --no-pager --full status fail2ban || true
  systemctl --no-pager --full status sing-box || true
}

show_banner() {
  cat <<'EOF'
========================================
rebuild-vps 一键脚本
说明：
- 仅支持 Debian 12/13
- 将修改 SSH 配置（端口 22222）
- 安装并配置 fail2ban、sysctl
- 安装 gvm + Go 1.25
- 使用 xcaddy 编译 Caddy
- 安装 1Panel（保持官方交互）
- 编译 sing-box v12.x
- 为所有用户安装 zsh + oh-my-zsh
========================================
EOF
}

show_system_info() {
  # 输出系统基本信息，供用户确认
  log "System information:"
  echo "  Hostname: $(hostname)"
  echo "  OS: $(. /etc/os-release && echo "${PRETTY_NAME}")"
  echo "  Kernel: $(uname -r)"
  echo "  CPU: $(lscpu | awk -F: '/Model name/ {gsub(/^[ \t]+/, "", $2); print $2; exit}')"
  echo "  CPU cores: $(nproc)"
  echo "  Memory: $(free -h | awk '/Mem:/ {print $2}')"
  echo "  Disk: $(lsblk -d -o SIZE,MODEL | tail -n +2 | tr '\n' '; ')"
  echo "  IPv4: $(ip -4 -o addr show | awk '{print $2 ":" $4}' | tr '\n' '; ')"
  echo "  IPv6: $(ip -6 -o addr show | awk '{print $2 ":" $4}' | tr '\n' '; ')"
}

confirm_continue() {
  # 等用户确认后再继续执行
  local answer
  read -r -p "确认继续安装？输入 yes 继续，其它任意键退出: " answer
  if [[ "${answer}" != "yes" && "${answer}" != "y" && "${answer}" != "Y" ]]; then
    die "User canceled."
  fi
}

parse_args() {
  # 支持：--skip-1panel / --skip-zsh / --skip-ufw / --only=xxx,yyy
  SKIP_1PANEL=0
  SKIP_ZSH=0
  SKIP_UFW=0
  ONLY=""
  for arg in "$@"; do
    case "${arg}" in
      --skip-1panel)
        SKIP_1PANEL=1
        ;;
      --skip-zsh)
        SKIP_ZSH=1
        ;;
      --skip-ufw)
        SKIP_UFW=1
        ;;
      --only=*)
        ONLY="${arg#--only=}"
        ;;
      *)
        ;;
    esac
  done
}

should_run() {
  # 若指定 --only，则只运行匹配模块
  local name="$1"
  if [[ -z "${ONLY}" ]]; then
    return 0
  fi
  IFS=',' read -r -a mods <<<"${ONLY}"
  for m in "${mods[@]}"; do
    if [[ "${m}" == "${name}" ]]; then
      return 0
    fi
  done
  return 1
}

main() {
  parse_args "$@"
  show_banner
  show_system_info
  confirm_continue

  if should_run "check"; then run_basic_checks; fi
  if should_run "ssh"; then configure_ssh; fi
  if should_run "fail2ban"; then install_fail2ban; fi
  if should_run "sysctl"; then apply_sysctl; fi
  if should_run "gvm"; then install_gvm_go; fi
  if should_run "caddy"; then install_caddy; fi

  if [[ "${SKIP_1PANEL}" -eq 0 ]]; then
    if should_run "1panel"; then install_1panel; fi
  else
    log "Skipping 1Panel installation."
  fi

  if should_run "singbox"; then install_sing_box; fi

  if [[ "${SKIP_ZSH}" -eq 0 ]]; then
    if should_run "zsh"; then install_zsh_ohmyzsh; fi
  else
    log "Skipping zsh/oh-my-zsh installation."
  fi

  if [[ "${SKIP_UFW}" -eq 0 ]]; then
    if should_run "ufw"; then install_ufw; fi
  else
    log "Skipping UFW installation."
  fi

  if should_run "summary"; then summary; fi
}

main "$@"
