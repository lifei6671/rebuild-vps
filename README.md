# rebuild-vps

这是第一个用于搭建VPS服务器常用工具和服务的项目。目前搭建的服务如下：

1. Caddy V2 版本用于反向代理和证书申请，使用 Cloudflare 管理域名配合 Caddy 下发证书。使用如下命令编译：
    ```
     xcaddy build v2.10.2  \
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
    --with github.com/mholt/caddy-ratelimit
    ```
    caddy 需要新建 caddy 账户，并在该账户下运行。
2. 1panel 用于日常VPS管理工作，通过 caddy 代理实现域名访问。安装过程中，需要用户确认自定义的设置。运行在root账户下。
3. sing-box 用于代理服务。运行在root账户下。

其他安全行为：

1. SSH加固，变更端口号以及设置常用不安全配置
2. 安装 fail2ban ，并启用最优配置
3. sysctl配置如下：
    ```
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
    # 建议：删除 tcp_mem 这一行（让系统自适应）
    # net.ipv4.tcp_mem = ...

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
    ```

## 快速安装（单脚本）

该项目提供单脚本安装方式，用于 Debian 12/13 快速初始化 VPS。

执行（在 Debian 12/13 的 root 账户）：

```bash
chmod +x scripts/rebuild-vps.sh
./scripts/rebuild-vps.sh
```

可选参数：

- `--skip-1panel`：跳过 1Panel 安装
- `--skip-zsh`：跳过 zsh + oh-my-zsh 安装
- `--only=模块1,模块2`：仅运行指定模块
  例如：`--only=check,ssh,fail2ban`

脚本内容包含：

- SSH 加固（端口 22222，允许 root 与密码登录）
- fail2ban 安装与常见模板配置
- sysctl 优化写入
- 使用 gvm 安装 Go 1.25，并通过 xcaddy 编译 Caddy
- 生成 Caddyfile（会提示输入 Cloudflare API Token）
- 调用 1Panel 官方安装脚本（保留交互）
- 编译 sing-box v12.x 并初始化最小配置
- 安装 zsh + oh-my-zsh，默认 shell 设为 zsh

注意事项：

- Caddyfile 会提示输入 Cloudflare API Token，并明文写入 `/etc/caddy/Caddyfile`。
- 1Panel 安装脚本为官方交互式安装，保持原有交互。
- sing-box 配置目录为 `/usr/local/etc/sing-box`，若无配置会初始化 `socks` 入站 + `direct` 出站。
