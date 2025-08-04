#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# 检查是否为root用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要root权限运行"
        log_info "请使用: sudo bash $0"
        exit 1
    fi
}

# 生成UUID
generate_uuid() {
    cat /proc/sys/kernel/random/uuid
}

# 生成随机字符串
generate_random_string() {
    openssl rand -hex 8
}

# 收集用户输入
collect_user_input() {
    log_step "收集配置信息"
    
    # 域名配置
    read -p "请输入主域名 (用于Reality): " MAIN_DOMAIN
    read -p "请输入第二个域名 (用于AnyTLS): " SECOND_DOMAIN
    
    # 反代网站
    read -p "请输入反代网站 [默认: www.lovelive-anime.jp]: " PROXY_WEBSITE
    PROXY_WEBSITE=${PROXY_WEBSITE:-www.lovelive-anime.jp}
    
    # Reality私钥
    read -p "请输入Reality私钥 [留空自动生成]: " REALITY_PRIVATE_KEY
    if [[ -z "$REALITY_PRIVATE_KEY" ]]; then
        REALITY_PRIVATE_KEY=$(generate_random_string)
        log_info "已生成Reality私钥: $REALITY_PRIVATE_KEY"
    fi
    
    # Reality短ID
    read -p "请输入Reality短ID [留空自动生成]: " REALITY_SHORT_ID
    if [[ -z "$REALITY_SHORT_ID" ]]; then
        REALITY_SHORT_ID=$(generate_random_string | cut -c1-6)
        log_info "已生成Reality短ID: $REALITY_SHORT_ID"
    fi
    
    # 生成UUID
    MAIN_UUID=$(generate_uuid)
    log_info "已生成主UUID: $MAIN_UUID"
    
    # 询问是否添加出站配置
    echo
    log_info "是否添加出站配置 (用于转发流量)？"
    read -p "输入 y/n [默认: n]: " ADD_OUTBOUNDS
    ADD_OUTBOUNDS=${ADD_OUTBOUNDS:-n}
    
    if [[ "$ADD_OUTBOUNDS" == "y" || "$ADD_OUTBOUNDS" == "Y" ]]; then
        log_info "请输入出站服务器信息 (格式: vless://uuid@domain:port?...)"
        read -p "出站服务器1 (可选): " OUTBOUND_1
        read -p "出站服务器2 (可选): " OUTBOUND_2
        read -p "出站服务器3 (可选): " OUTBOUND_3
        read -p "出站服务器4 (可选): " OUTBOUND_4
    fi
    
    # 确认信息
    echo
    log_step "配置信息确认"
    echo "主域名: $MAIN_DOMAIN"
    echo "第二域名: $SECOND_DOMAIN"
    echo "反代网站: $PROXY_WEBSITE"
    echo "主UUID: $MAIN_UUID"
    echo "Reality私钥: $REALITY_PRIVATE_KEY"
    echo "Reality短ID: $REALITY_SHORT_ID"
    echo
    read -p "确认配置信息是否正确？(y/n): " CONFIRM
    if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
        log_error "用户取消操作"
        exit 1
    fi
}

# 安装系统依赖
install_dependencies() {
    log_step "安装系统依赖"
    
    apt update
    apt install -y curl sudo wget git unzip nano vim socat cron nginx-full
    
    if [[ $? -ne 0 ]]; then
        log_error "系统依赖安装失败"
        exit 1
    fi
    
    log_info "系统依赖安装完成"
}

# 安装sing-box
install_singbox() {
    log_step "安装sing-box"
    
    bash <(curl -fsSL https://sing-box.app/deb-install.sh)
    
    if [[ $? -ne 0 ]]; then
        log_error "sing-box安装失败"
        exit 1
    fi
    
    log_info "sing-box安装完成"
}

# 安装acme.sh
install_acme() {
    log_step "安装acme.sh"
    
    curl https://get.acme.sh | sh
    ln -sf /root/.acme.sh/acme.sh /usr/local/bin/acme.sh
    
    # 切换CA
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    
    if [[ $? -ne 0 ]]; then
        log_error "acme.sh安装失败"
        exit 1
    fi
    
    log_info "acme.sh安装完成"
}

# 申请SSL证书
request_certificate() {
    log_step "申请SSL证书"
    
    # 停止可能占用80端口的服务
    systemctl stop nginx 2>/dev/null
    systemctl stop apache2 2>/dev/null
    
    # 申请证书
    /root/.acme.sh/acme.sh --issue -d "$MAIN_DOMAIN" -d "$SECOND_DOMAIN" --standalone
    
    if [[ $? -ne 0 ]]; then
        log_error "SSL证书申请失败"
        log_info "请检查域名解析是否正确指向本服务器"
        exit 1
    fi
    
    # 创建证书目录
    mkdir -p /etc/ssl/private
    
    # 安装证书
    /root/.acme.sh/acme.sh --install-cert -d "$MAIN_DOMAIN" \
        --key-file /etc/ssl/private/private.key \
        --fullchain-file /etc/ssl/private/fullchain.cer
    
    if [[ $? -ne 0 ]]; then
        log_error "SSL证书安装失败"
        exit 1
    fi
    
    log_info "SSL证书申请和安装完成"
}

# 生成sing-box配置
generate_singbox_config() {
    log_step "生成sing-box配置文件"
    
    # 创建配置目录
    mkdir -p /etc/sing-box
    
    # 生成配置文件
    cat > /etc/sing-box/config.json << EOF
{
    "inbounds": [
        {
            "tag": "reality",
            "type": "vless",
            "listen": "127.0.0.1",
            "listen_port": 8443,
            "users": [
                {
                    "name": "main-user",
                    "uuid": "$MAIN_UUID",
                    "flow": "xtls-rprx-vision"
                }
            ],
            "tls": {
                "enabled": true,
                "server_name": "$MAIN_DOMAIN",
                "reality": {
                    "enabled": true,
                    "handshake": {
                        "server": "127.0.0.1",
                        "server_port": 8001
                    },
                    "private_key": "$REALITY_PRIVATE_KEY",
                    "short_id": [
                        "$REALITY_SHORT_ID"
                    ]
                }
            }
        },
        {
            "tag": "vision",
            "type": "vless",
            "listen": "::",
            "listen_port": 28790,
            "users": [
                {
                    "uuid": "$MAIN_UUID",
                    "flow": "xtls-rprx-vision"
                }
            ],
            "tls": {
                "enabled": true,
                "certificate_path": "/etc/ssl/private/fullchain.cer",
                "key_path": "/etc/ssl/private/private.key"
            }
        },
        {
            "tag": "hysteria2",
            "type": "hysteria2",
            "listen": "::",
            "listen_port": 38790,
            "up_mbps": 50,
            "down_mbps": 300,
            "users": [
                {
                    "password": "$MAIN_UUID"
                }
            ],
            "tls": {
                "enabled": true,
                "alpn": [
                    "h3"
                ],
                "certificate_path": "/etc/ssl/private/fullchain.cer",
                "key_path": "/etc/ssl/private/private.key"
            }
        },
        {
            "tag": "anytls",
            "type": "anytls",
            "listen": "::",
            "listen_port": 48790,
            "users": [
                {
                 "password": "$MAIN_UUID"
                }
            ],
            "tls": {
                "enabled": true,
                "server_name": "$SECOND_DOMAIN",
                "certificate_path": "/etc/ssl/private/fullchain.cer",
                "key_path": "/etc/ssl/private/private.key"
            }
        }
    ],
    "outbounds": [
        {
            "tag": "direct",
            "type": "direct"
        }
    ],
    "route": {
        "rules": [
            {
                "inbound": ["reality"],
                "outbound": "direct"
            },
            {
                "inbound": ["vision"],
                "outbound": "direct"
            },
            {
                "inbound": ["hysteria2"],
                "outbound": "direct"
            },
            {
                "inbound": ["anytls"],
                "outbound": "direct"
            },
            {
                "outbound": "direct"
            }
        ]
    }
}
EOF
    
    log_info "sing-box配置文件生成完成"
}

# 生成nginx配置
generate_nginx_config() {
    log_step "生成nginx配置文件"
    
    # 备份原配置
    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup
    
    # 生成新配置
    cat > /etc/nginx/nginx.conf << EOF
# 加载动态模块
load_module modules/ngx_stream_module.so;

user root;
worker_processes auto;
error_log /var/log/nginx/error.log notice;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

# Stream模块用于SNI过滤
stream {
    # 定义允许的SNI列表的map
    map \$ssl_preread_server_name \$backend_pool {
        $MAIN_DOMAIN backend;
        default drop;
    }
    
    # 定义后端服务器（sing-box）
    upstream backend {
        server 127.0.0.1:8443;
    }
    
    # 丢弃非法请求的后端
    upstream drop {
        server 127.0.0.1:9999;
    }
    
    # 443端口的SNI过滤服务器
    server {
        listen 443;
        listen [::]:443;
        ssl_preread on;
        proxy_pass \$backend_pool;
        proxy_timeout 3s;
        proxy_responses 1;
        error_log /var/log/nginx/stream_error.log;
    }
    
    # 记录被拒绝的连接
    server {
        listen 127.0.0.1:9999;
        return 444;
    }
}

# HTTP模块
http {
    log_format main '[\$time_local] \$proxy_protocol_addr "\$http_referer" "\$http_user_agent"';
    access_log /var/log/nginx/access.log main;
    
    map \$http_upgrade \$connection_upgrade {
        default upgrade;
        ""      close;
    }
    
    map \$proxy_protocol_addr \$proxy_forwarded_elem {
        ~^[0-9.]+\$        "for=\$proxy_protocol_addr";
        ~^[0-9A-Fa-f:.]+\$ "for=\"[\$proxy_protocol_addr]\"";
        default           "for=unknown";
    }
    
    map \$http_forwarded \$proxy_add_forwarded {
        "~^(,[ \\\\t]*)*([!#\$%&'*+.^_\`|~0-9A-Za-z-]+=([!#\$%&'*+.^_\`|~0-9A-Za-z-]+|\"([\\\\t \\\\x21\\\\x23-\\\\x5B\\\\x5D-\\\\x7E\\\\x80-\\\\xFF]|\\\\\\\\[\\\\t \\\\x21-\\\\x7E\\\\x80-\\\\xFF])*\"))?(;([!#\$%&'*+.^_\`|~0-9A-Za-z-]+=([!#\$%&'*+.^_\`|~0-9A-Za-z-]+|\"([\\\\t \\\\x21\\\\x23-\\\\x5B\\\\x5D-\\\\x7E\\\\x80-\\\\xFF]|\\\\\\\\[\\\\t \\\\x21-\\\\x7E\\\\x80-\\\\xFF])*\"))?)*([ \\\\t]*,([ \\\\t]*([!#\$%&'*+.^_\`|~0-9A-Za-z-]+=([!#\$%&'*+.^_\`|~0-9A-Za-z-]+|\"([\\\\t \\\\x21\\\\x23-\\\\x5B\\\\x5D-\\\\x7E\\\\x80-\\\\xFF]|\\\\\\\\[\\\\t \\\\x21-\\\\x7E\\\\x80-\\\\xFF])*\"))?(;([!#\$%&'*+.^_\`|~0-9A-Za-z-]+=([!#\$%&'*+.^_\`|~0-9A-Za-z-]+|\"([\\\\t \\\\x21\\\\x23-\\\\x5B\\\\x5D-\\\\x7E\\\\x80-\\\\xFF]|\\\\\\\\[\\\\t \\\\x21-\\\\x7E\\\\x80-\\\\xFF])*\"))?)*)?)*\$" "\$http_forwarded, \$proxy_forwarded_elem";
        default "\$proxy_forwarded_elem";
    }
    
    # HTTP重定向到HTTPS
    server {
        listen 80;
        listen [::]:80;
        return 301 https://\$host\$request_uri;
    }
    
    # 反向代理服务器（仅供内部使用）
    server {
        listen 127.0.0.1:8001 ssl http2;
        set_real_ip_from 127.0.0.1;
        real_ip_header proxy_protocol;
        server_name $MAIN_DOMAIN;
        
        ssl_certificate /etc/ssl/private/fullchain.cer;
        ssl_certificate_key /etc/ssl/private/private.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers TLS13_AES_128_GCM_SHA256:TLS13_AES_256_GCM_SHA384:TLS13_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
        ssl_prefer_server_ciphers on;
        ssl_stapling on;
        ssl_stapling_verify on;
        resolver 1.1.1.1 valid=60s;
        resolver_timeout 2s;
        
        location / {
            sub_filter \$proxy_host \$host;
            sub_filter_once off;
            set \$website $PROXY_WEBSITE;
            proxy_pass https://\$website;
            resolver 1.1.1.1;
            proxy_set_header Host \$proxy_host;
            proxy_http_version 1.1;
            proxy_cache_bypass \$http_upgrade;
            proxy_ssl_server_name on;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection \$connection_upgrade;
            proxy_set_header X-Real-IP \$proxy_protocol_addr;
            proxy_set_header Forwarded \$proxy_add_forwarded;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
            proxy_set_header X-Forwarded-Host \$host;
            proxy_set_header X-Forwarded-Port \$server_port;
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
        }
    }
}
EOF
    
    log_info "nginx配置文件生成完成"
}

# 启动服务
start_services() {
    log_step "启动服务"
    
    # 检查nginx配置
    nginx -t
    if [[ $? -ne 0 ]]; then
        log_error "nginx配置文件检查失败"
        exit 1
    fi
    
    # 启动服务
    systemctl enable sing-box nginx
    systemctl restart sing-box
    systemctl restart nginx
    
    # 检查服务状态
    if systemctl is-active --quiet sing-box; then
        log_info "sing-box服务启动成功"
    else
        log_error "sing-box服务启动失败"
        systemctl status sing-box
        exit 1
    fi
    
    if systemctl is-active --quiet nginx; then
        log_info "nginx服务启动成功"
    else
        log_error "nginx服务启动失败"
        systemctl status nginx
        exit 1
    fi
}

# 生成客户端配置信息
generate_client_configs() {
    log_step "生成客户端配置信息"
    
    echo
    log_info "=== 客户端配置信息 ==="
    echo
    echo "1. VLESS Reality 配置:"
    echo "   服务器: $MAIN_DOMAIN"
    echo "   端口: 443"
    echo "   UUID: $MAIN_UUID"
    echo "   传输协议: tcp"
    echo "   流控: xtls-rprx-vision"
    echo "   TLS: reality"
    echo "   SNI: $MAIN_DOMAIN"
    echo "   私钥: $REALITY_PRIVATE_KEY"
    echo "   短ID: $REALITY_SHORT_ID"
    echo
    echo "2. VLESS Vision 配置:"
    echo "   服务器: $MAIN_DOMAIN"
    echo "   端口: 28790"
    echo "   UUID: $MAIN_UUID"
    echo "   传输协议: tcp"
    echo "   流控: xtls-rprx-vision"
    echo "   TLS: 启用"
    echo "   SNI: $MAIN_DOMAIN"
    echo
    echo "3. Hysteria2 配置:"
    echo "   服务器: $MAIN_DOMAIN"
    echo "   端口: 38790"
    echo "   密码: $MAIN_UUID"
    echo "   TLS: 启用"
    echo "   SNI: $MAIN_DOMAIN"
    echo
    echo "4. AnyTLS 配置:"
    echo "   服务器: $SECOND_DOMAIN"
    echo "   端口: 48790"
    echo "   密码: $MAIN_UUID"
    echo "   TLS: 启用"
    echo "   SNI: $SECOND_DOMAIN"
    echo
    
    # 保存配置到文件
    cat > /root/client-configs.txt << EOF
=== 客户端配置信息 ===

1. VLESS Reality 配置:
   服务器: $MAIN_DOMAIN
   端口: 443
   UUID: $MAIN_UUID
   传输协议: tcp
   流控: xtls-rprx-vision
   TLS: reality
   SNI: $MAIN_DOMAIN
   私钥: $REALITY_PRIVATE_KEY
   短ID: $REALITY_SHORT_ID

2. VLESS Vision 配置:
   服务器: $MAIN_DOMAIN
   端口: 28790
   UUID: $MAIN_UUID
   传输协议: tcp
   流控: xtls-rprx-vision
   TLS: 启用
   SNI: $MAIN_DOMAIN

3. Hysteria2 配置:
   服务器: $MAIN_DOMAIN
   端口: 38790
   密码: $MAIN_UUID
   TLS: 启用
   SNI: $MAIN_DOMAIN

4. AnyTLS 配置:
   服务器: $SECOND_DOMAIN
   端口: 48790
   密码: $MAIN_UUID
   TLS: 启用
   SNI: $SECOND_DOMAIN

配置文件路径:
- sing-box: /etc/sing-box/config.json
- nginx: /etc/nginx/nginx.conf
- SSL证书: /etc/ssl/private/

常用命令:
- 重启sing-box: systemctl restart sing-box
- 重启nginx: systemctl restart nginx
- 查看sing-box日志: journalctl -u sing-box -f
- 查看nginx日志: tail -f /var/log/nginx/error.log
EOF
    
    log_info "客户端配置信息已保存到 /root/client-configs.txt"
}

# 主函数
main() {
    echo -e "${BLUE}"
    echo "=================================================="
    echo "        sing-box + nginx 一键部署脚本"
    echo "=================================================="
    echo -e "${NC}"
    
    check_root
    collect_user_input
    install_dependencies
    install_singbox
    install_acme
    request_certificate
    generate_singbox_config
    generate_nginx_config
    start_services
    generate_client_configs
    
    echo
    log_info "=== 部署完成 ==="
    log_info "所有服务已成功部署并启动"
    log_info "客户端配置信息请查看上方输出或 /root/client-configs.txt 文件"
    log_warn "请确保防火墙已开放相应端口: 80, 443, 28790, 38790, 48790"
    echo
}

# 运行主函数
main "$@"
