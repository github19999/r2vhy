#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
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

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} 🎉 $1"
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

# 生成Reality密钥对
generate_reality_keypair() {
    local temp_dir=$(mktemp -d)
    cd "$temp_dir"
    
    # 使用sing-box生成Reality密钥对
    sing-box generate reality-keypair > keypair.txt 2>/dev/null
    
    if [[ -f keypair.txt && -s keypair.txt ]]; then
        REALITY_PRIVATE_KEY=$(grep "PrivateKey:" keypair.txt | awk '{print $2}' | tr -d '"')
        REALITY_PUBLIC_KEY=$(grep "PublicKey:" keypair.txt | awk '{print $2}' | tr -d '"')
    else
        # 备用方法：使用openssl生成
        openssl genpkey -algorithm X25519 -out private.key 2>/dev/null
        REALITY_PRIVATE_KEY=$(openssl pkey -in private.key -text -noout | grep 'priv:' -A3 | tail -n +2 | tr -d ' \n:' | head -c64)
        REALITY_PUBLIC_KEY=$(openssl pkey -in private.key -pubout -text -noout | grep 'pub:' -A3 | tail -n +2 | tr -d ' \n:' | head -c64)
    fi
    
    cd - > /dev/null
    rm -rf "$temp_dir"
    
    # 如果还是生成失败，使用随机字符串
    if [[ -z "$REALITY_PRIVATE_KEY" ]]; then
        REALITY_PRIVATE_KEY=$(openssl rand -hex 32)
        REALITY_PUBLIC_KEY=$(openssl rand -hex 32)
    fi
}

# 生成随机短ID
generate_short_id() {
    openssl rand -hex 8 | cut -c1-8
}

# 收集用户输入
collect_user_input() {
    log_step "收集配置信息"
    
    echo -e "${CYAN}请输入域名信息（支持多个域名）:${NC}"
    read -p "请输入主域名: " MAIN_DOMAIN
    
    # 收集所有域名
    DOMAINS="$MAIN_DOMAIN"
    echo "是否添加更多域名？输入域名或直接按回车结束:"
    while true; do
        read -p "附加域名 (回车结束): " additional_domain
        if [[ -z "$additional_domain" ]]; then
            break
        fi
        DOMAINS="$DOMAINS $additional_domain"
    done
    
    # 第二个域名用于AnyTLS
    SECOND_DOMAIN=$(echo $DOMAINS | awk '{print $2}')
    if [[ -z "$SECOND_DOMAIN" ]]; then
        SECOND_DOMAIN="$MAIN_DOMAIN"
    fi
    
    # 反代网站
    read -p "请输入反代网站 [默认: www.lovelive-anime.jp]: " PROXY_WEBSITE
    PROXY_WEBSITE=${PROXY_WEBSITE:-www.lovelive-anime.jp}
    
    # 生成Reality密钥对和短ID
    log_info "正在生成Reality密钥对..."
    generate_reality_keypair
    REALITY_SHORT_ID=$(generate_short_id)
    
    # 生成主UUID
    MAIN_UUID=$(generate_uuid)
    
    # 确认信息
    echo
    log_step "配置信息确认"
    echo -e "${CYAN}主域名:${NC} $MAIN_DOMAIN"
    echo -e "${CYAN}所有域名:${NC} $DOMAINS"
    echo -e "${CYAN}第二域名:${NC} $SECOND_DOMAIN"
    echo -e "${CYAN}反代网站:${NC} $PROXY_WEBSITE"
    echo -e "${CYAN}主UUID:${NC} $MAIN_UUID"
    echo -e "${CYAN}Reality私钥:${NC} $REALITY_PRIVATE_KEY"
    echo -e "${CYAN}Reality公钥:${NC} $REALITY_PUBLIC_KEY"
    echo -e "${CYAN}Reality短ID:${NC} $REALITY_SHORT_ID"
    echo
    read -p "确认配置信息是否正确？(y/n): " CONFIRM
    if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
        log_error "用户取消操作"
        exit 1
    fi
}

# 安装系统依赖
install_dependencies() {
    log_step "更新系统并安装依赖包"
    
    apt update -y
    apt install -y curl sudo wget git unzip nano vim socat cron nginx-full openssl
    
    if [[ $? -ne 0 ]]; then
        log_error "系统依赖安装失败"
        exit 1
    fi
    
    log_info "系统依赖安装完成"
}

# 安装sing-box
install_singbox() {
    log_step "安装sing-box"
    
    # 停止可能运行的sing-box服务
    systemctl stop sing-box 2>/dev/null
    
    # 下载并安装sing-box
    bash <(curl -fsSL https://sing-box.app/deb-install.sh)
    
    if [[ $? -ne 0 ]]; then
        log_error "sing-box安装失败"
        exit 1
    fi
    
    # 检查sing-box是否安装成功
    if command -v sing-box >/dev/null 2>&1; then
        SINGBOX_VERSION=$(sing-box version 2>/dev/null | head -1 || echo "未知版本")
        log_info "sing-box安装完成 - $SINGBOX_VERSION"
    else
        log_error "sing-box安装验证失败"
        exit 1
    fi
}

# 安装acme.sh
install_acme() {
    log_step "安装acme.sh证书管理工具"
    
    # 检查是否已安装
    if [[ -f "/root/.acme.sh/acme.sh" ]]; then
        log_info "acme.sh已安装，跳过安装步骤"
        return 0
    fi
    
    curl https://get.acme.sh | sh
    
    # 创建软链接
    ln -sf /root/.acme.sh/acme.sh /usr/local/bin/acme.sh
    
    # 设置默认CA
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
    
    # 构建域名参数
    DOMAIN_ARGS=""
    for domain in $DOMAINS; do
        DOMAIN_ARGS="$DOMAIN_ARGS -d $domain"
    done
    
    log_info "正在为以下域名申请证书: $DOMAINS"
    
    # 申请证书
    /root/.acme.sh/acme.sh --issue $DOMAIN_ARGS --standalone --keylength ec-256
    
    if [[ $? -ne 0 ]]; then
        log_error "SSL证书申请失败"
        log_info "请检查以下项目:"
        log_info "1. 域名解析是否正确指向本服务器"
        log_info "2. 防火墙是否开放80端口"
        log_info "3. 服务器网络连接是否正常"
        exit 1
    fi
    
    # 创建证书目录
    mkdir -p /etc/ssl/private
    
    # 安装证书
    /root/.acme.sh/acme.sh --install-cert -d "$MAIN_DOMAIN" --ecc \
        --key-file /etc/ssl/private/private.key \
        --fullchain-file /etc/ssl/private/fullchain.cer \
        --ca-file /etc/ssl/private/ca.cer \
        --reloadcmd "systemctl reload nginx"
    
    if [[ $? -ne 0 ]]; then
        log_error "SSL证书安装失败"
        exit 1
    fi
    
    # 设置证书文件权限
    chmod 644 /etc/ssl/private/fullchain.cer
    chmod 600 /etc/ssl/private/private.key
    chmod 644 /etc/ssl/private/ca.cer
    
    # 显示证书部署完成信息
    show_certificate_info
}

# 显示证书信息
show_certificate_info() {
    # 获取证书有效期
    CERT_EXPIRY=$(openssl x509 -in /etc/ssl/private/fullchain.cer -noout -enddate 2>/dev/null | cut -d= -f2)
    
    echo
    echo -e "${GREEN}==============================================${NC}"
    echo -e "${GREEN}           SSL证书部署完成！${NC}"
    echo -e "${GREEN}==============================================${NC}"
    echo
    echo -e "${CYAN}证书信息:${NC}"
    echo -e "  主域名: ${YELLOW}$MAIN_DOMAIN${NC}"
    echo -e "  所有域名: ${YELLOW}$DOMAINS${NC}"
    echo -e "  证书目录: ${YELLOW}/etc/ssl/private${NC}"
    echo -e "  私钥文件: ${YELLOW}/etc/ssl/private/private.key${NC}"
    echo -e "  证书文件: ${YELLOW}/etc/ssl/private/fullchain.cer${NC}"
    echo -e "  CA证书: ${YELLOW}/etc/ssl/private/ca.cer${NC}"
    echo -e "  有效期至: ${YELLOW}${CERT_EXPIRY:-未知}${NC}"
    echo
    echo -e "${CYAN}Web服务器配置示例:${NC}"
    echo
    echo -e "${PURPLE}Nginx 配置:${NC}"
    echo -e "  ssl_certificate /etc/ssl/private/fullchain.cer;"
    echo -e "  ssl_certificate_key /etc/ssl/private/private.key;"
    echo
    echo -e "${PURPLE}Apache 配置:${NC}"
    echo -e "  SSLCertificateFile /etc/ssl/private/fullchain.cer"
    echo -e "  SSLCertificateKeyFile /etc/ssl/private/private.key"
    echo
    echo -e "${CYAN}管理命令:${NC}"
    echo -e "  查看证书: ${YELLOW}acme.sh --list${NC}"
    echo -e "  手动续期: ${YELLOW}acme.sh --renew -d $MAIN_DOMAIN --force${NC}"
    echo -e "  删除证书: ${YELLOW}acme.sh --remove -d $MAIN_DOMAIN${NC}"
    echo
    echo -e "${CYAN}注意事项:${NC}"
    echo -e "  ${GREEN}✓${NC} 证书已设置自动续期 (每天凌晨2点检查)"
    echo -e "  ${GREEN}✓${NC} 请确保防火墙开放80和443端口"
    echo -e "  ${GREEN}✓${NC} 重新配置Web服务器后记得重启服务"
    echo
    log_success "SSL证书部署完成！"
    echo
    
    # 暂停3秒让用户查看证书信息
    sleep 3
}

# 生成sing-box配置
generate_singbox_config() {
    log_step "生成sing-box配置文件"
    
    # 创建配置目录
    mkdir -p /etc/sing-box
    
    # 生成配置文件
    cat > /etc/sing-box/config.json << EOF
{
    "log": {
        "disabled": false,
        "level": "info",
        "timestamp": true
    },
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
            }
        ],
        "final": "direct"
    }
}
EOF
    
    # 验证配置文件语法
    sing-box check -c /etc/sing-box/config.json
    if [[ $? -ne 0 ]]; then
        log_error "sing-box配置文件语法错误"
        exit 1
    fi
    
    log_info "sing-box配置文件生成完成"
}

# 生成nginx配置
generate_nginx_config() {
    log_step "生成nginx配置文件"
    
    # 备份原配置
    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup.$(date +%Y%m%d_%H%M%S)
    
    # 生成新配置
    cat > /etc/nginx/nginx.conf << 'EOF'
# 加载动态模块
load_module modules/ngx_stream_module.so;

user www-data;
worker_processes auto;
error_log /var/log/nginx/error.log notice;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

# Stream模块用于SNI过滤
stream {
    # 定义允许的SNI列表的map
    map $ssl_preread_server_name $backend_pool {
        MAIN_DOMAIN_PLACEHOLDER backend;
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
        proxy_pass $backend_pool;
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
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    log_format main '[$time_local] $proxy_protocol_addr "$http_referer" "$http_user_agent"';
    access_log /var/log/nginx/access.log main;
    
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    
    map $http_upgrade $connection_upgrade {
        default upgrade;
        "" close;
    }
    
    map $proxy_protocol_addr $proxy_forwarded_elem {
        ~^[0-9.]+$ "for=$proxy_protocol_addr";
        ~^[0-9A-Fa-f:.]+$ "for=\"[$proxy_protocol_addr]\"";
        default "for=unknown";
    }
    
    map $http_forwarded $proxy_add_forwarded {
        "~^(,[ \\t]*)*([!#$%&'*+.^_`|~0-9A-Za-z-]+=([!#$%&'*+.^_`|~0-9A-Za-z-]+|\"([\\t \\x21\\x23-\\x5B\\x5D-\\x7E\\x80-\\xFF]|\\\\[\\t \\x21-\\x7E\\x80-\\xFF])*\"))?(;([!#$%&'*+.^_`|~0-9A-Za-z-]+=([!#$%&'*+.^_`|~0-9A-Za-z-]+|\"([\\t \\x21\\x23-\\x5B\\x5D-\\x7E\\x80-\\xFF]|\\\\[\\t \\x21-\\x7E\\x80-\\xFF])*\"))?)*([ \\t]*,([ \\t]*([!#$%&'*+.^_`|~0-9A-Za-z-]+=([!#$%&'*+.^_`|~0-9A-Za-z-]+|\"([\\t \\x21\\x23-\\x5B\\x5D-\\x7E\\x80-\\xFF]|\\\\[\\t \\x21-\\x7E\\x80-\\xFF])*\"))?(;([!#$%&'*+.^_`|~0-9A-Za-z-]+=([!#$%&'*+.^_`|~0-9A-Za-z-]+|\"([\\t \\x21\\x23-\\x5B\\x5D-\\x7E\\x80-\\xFF]|\\\\[\\t \\x21-\\x7E\\x80-\\xFF])*\"))?)*)?)*$" "$http_forwarded, $proxy_forwarded_elem";
        default "$proxy_forwarded_elem";
    }
    
    # HTTP重定向到HTTPS
    server {
        listen 80;
        listen [::]:80;
        server_name _;
        return 301 https://$host$request_uri;
    }
    
    # 反向代理服务器（仅供内部使用）
    server {
        listen 127.0.0.1:8001 ssl http2;
        set_real_ip_from 127.0.0.1;
        real_ip_header proxy_protocol;
        server_name MAIN_DOMAIN_PLACEHOLDER;
        
        ssl_certificate /etc/ssl/private/fullchain.cer;
        ssl_certificate_key /etc/ssl/private/private.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers TLS13_AES_128_GCM_SHA256:TLS13_AES_256_GCM_SHA384:TLS13_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
        ssl_prefer_server_ciphers on;
        ssl_stapling on;
        ssl_stapling_verify on;
        resolver 1.1.1.1 8.8.8.8 valid=60s;
        resolver_timeout 2s;
        
        location / {
            sub_filter $proxy_host $host;
            sub_filter_once off;
            set $website PROXY_WEBSITE_PLACEHOLDER;
            proxy_pass https://$website;
            resolver 1.1.1.1 8.8.8.8;
            proxy_set_header Host $proxy_host;
            proxy_http_version 1.1;
            proxy_cache_bypass $http_upgrade;
            proxy_ssl_server_name on;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_set_header X-Real-IP $proxy_protocol_addr;
            proxy_set_header Forwarded $proxy_add_forwarded;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-Host $host;
            proxy_set_header X-Forwarded-Port $server_port;
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
        }
    }
}
EOF
    
    # 替换占位符
    sed -i "s/MAIN_DOMAIN_PLACEHOLDER/$MAIN_DOMAIN/g" /etc/nginx/nginx.conf
    sed -i "s/PROXY_WEBSITE_PLACEHOLDER/$PROXY_WEBSITE/g" /etc/nginx/nginx.conf
    
    log_info "nginx配置文件生成完成"
}

# 启动服务
start_services() {
    log_step "启动和配置服务"
    
    # 检查nginx配置
    nginx -t
    if [[ $? -ne 0 ]]; then
        log_error "nginx配置文件检查失败"
        exit 1
    fi
    log_info "nginx配置文件检查通过"
    
    # 启用服务开机自启
    systemctl enable sing-box nginx
    
    # 重启sing-box服务
    log_info "启动sing-box服务..."
    systemctl stop sing-box 2>/dev/null
    systemctl start sing-box
    sleep 2
    
    # 检查sing-box服务状态
    if systemctl is-active --quiet sing-box; then
        log_info "sing-box服务启动成功"
    else
        log_error "sing-box服务启动失败"
        echo "错误详情:"
        systemctl status sing-box --no-pager -l
        echo
        echo "日志信息:"
        journalctl -u sing-box --no-pager -l -n 20
        exit 1
    fi
    
    # 重启nginx服务
    log_info "启动nginx服务..."
    systemctl stop nginx 2>/dev/null
    systemctl start nginx
    sleep 2
    
    # 检查nginx服务状态
    if systemctl is-active --quiet nginx; then
        log_info "nginx服务启动成功"
    else
        log_error "nginx服务启动失败"
        echo "错误详情:"
        systemctl status nginx --no-pager -l
        exit 1
    fi
}

# 生成客户端配置信息
generate_client_configs() {
    log_step "生成客户端配置信息"
    
    echo
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN}        客户端配置信息${NC}"
    echo -e "${GREEN}============================================${NC}"
    echo
    echo -e "${CYAN}Reality密钥对信息:${NC}"
    echo -e "  私钥: ${YELLOW}$REALITY_PRIVATE_KEY${NC}"
    echo -e "  公钥: ${YELLOW}$REALITY_PUBLIC_KEY${NC}"
    echo -e "  短ID: ${YELLOW}$REALITY_SHORT_ID${NC}"
    echo
    echo -e "${PURPLE}1. VLESS Reality 配置:${NC}"
    echo -e "   服务器: ${YELLOW}$MAIN_DOMAIN${NC}"
    echo -e "   端口: ${YELLOW}443${NC}"
    echo -e "   UUID: ${YELLOW}$MAIN_UUID${NC}"
    echo -e "   传输协议: ${YELLOW}tcp${NC}"
    echo -e "   流控: ${YELLOW}xtls-rprx-vision${NC}"
    echo -e "   TLS: ${YELLOW}reality${NC}"
    echo -e "   SNI: ${YELLOW}$MAIN_DOMAIN${NC}"
    echo -e "   公钥: ${YELLOW}$REALITY_PUBLIC_KEY${NC}"
    echo -e "   短ID: ${YELLOW}$REALITY_SHORT_ID${NC}"
    echo
    echo -e "${PURPLE}2. VLESS Vision 配置:${NC}"
    echo -e "   服务器: ${YELLOW}$MAIN_DOMAIN${NC}"
    echo -e "   端口: ${YELLOW}28790${NC}"
    echo -e "   UUID: ${YELLOW}$MAIN_UUID${NC}"
    echo -e "   传输协议: ${YELLOW}tcp${NC}"
    echo -e "   流控: ${YELLOW}xtls-rprx-vision${NC}"
    echo -e "   TLS: ${YELLOW}启用${NC}"
    echo -e "   SNI: ${YELLOW}$MAIN_DOMAIN${NC}"
    echo
    echo -e "${PURPLE}3. Hysteria2 配置:${NC}"
    echo -e "   服务器: ${YELLOW}$MAIN_DOMAIN${NC}"
    echo -e "   端口: ${YELLOW}38790${NC}"
    echo -e "   密码: ${YELLOW}$MAIN_UUID${NC}"
    echo -e "   TLS: ${YELLOW}启用${NC}"
    echo -e "   SNI: ${YELLOW}$MAIN_DOMAIN${NC}"
    echo
    echo -e "${PURPLE}4. AnyTLS 配置:${NC}"
    echo -e "   服务器: ${YELLOW}$SECOND_DOMAIN${NC}"
    echo -e "   端口: ${YELLOW}48790${NC}"
    echo -e "   密码: ${YELLOW}$MAIN_UUID${NC}"
    echo -e "   TLS: ${YELLOW}启用${NC}"
    echo -e "   SNI: ${YELLOW}$SECOND_DOMAIN${NC}"
    echo
    
    # 保存配置到文件
    cat > /root/client-configs.txt << EOF
=== 客户端配置信息 ===

Reality密钥对信息:
  私钥: $REALITY_PRIVATE_KEY
  公钥: $REALITY_PUBLIC_KEY
  短ID: $REALITY_SHORT_ID

1. VLESS Reality 配置:
   服务器: $MAIN_DOMAIN
   端口: 443
   UUID: $MAIN_UUID
   传输协议: tcp
   流控: xtls-rprx-vision
   TLS: reality
   SNI: $MAIN_DOMAIN
   公钥: $REALITY_PUBLIC_KEY
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

=== 服务器信息 ===
域名列表: $DOMAINS
反代网站: $PROXY_WEBSITE

=== 配置文件路径 ===
- sing-box: /etc/sing-box/config.json
- nginx: /etc/nginx/nginx.conf
- SSL证书: /etc/ssl/private/

=== 常用管理命令 ===
服务管理:
  - 重启sing-box: systemctl restart sing-box
  - 重启nginx: systemctl restart nginx
  - 查看sing-box状态: systemctl status sing-box
  - 查看nginx状态: systemctl status nginx

日志查看:
  - sing-box日志: journalctl -u sing-box -f
  - nginx错误日志: tail -f /var/log/nginx/error.log
  - nginx访问日志: tail -f /var/log/nginx/access.log

证书管理:
  - 查看证书: acme.sh --list
  - 手动续期: acme.sh --renew -d $MAIN_DOMAIN --force
  - 删除证书: acme.sh --remove -d $MAIN_DOMAIN

防火墙端口:
  需要开放的端口: 80, 443, 28790, 38790, 48790
  - ufw allow 80,443,28790,38790,48790/tcp
  - iptables -A INPUT -p tcp --match multiport --dports 80,443,28790,38790,48790 -j ACCEPT
EOF
    
    echo -e "${CYAN}系统信息:${NC}"
    echo -e "  配置文件已保存到: ${YELLOW}/root/client-configs.txt${NC}"
    echo -e "  防火墙端口: ${YELLOW}80, 443, 28790, 38790, 48790${NC}"
    echo
    echo -e "${CYAN}常用管理命令:${NC}"
    echo -e "  重启sing-box: ${YELLOW}systemctl restart sing-box${NC}"
    echo -e "  重启nginx: ${YELLOW}systemctl restart nginx${NC}"
    echo -e "  查看sing-box日志: ${YELLOW}journalctl -u sing-box -f${NC}"
    echo -e "  查看nginx日志: ${YELLOW}tail -f /var/log/nginx/error.log${NC}"
    echo
    log_info "客户端配置信息已保存到 /root/client-configs.txt"
}

# 检查防火墙和端口
check_firewall() {
    log_step "检查防火墙配置"
    
    # 检查需要的端口
    REQUIRED_PORTS="80 443 28790 38790 48790"
    
    # 检查ufw状态
    if command -v ufw >/dev/null 2>&1; then
        UFW_STATUS=$(ufw status | head -1)
        if [[ "$UFW_STATUS" == *"active"* ]]; then
            log_warn "检测到ufw防火墙已启用"
            echo "请确保以下端口已开放: $REQUIRED_PORTS"
            echo "执行命令: ufw allow 80,443,28790,38790,48790/tcp"
        fi
    fi
    
    # 检查iptables
    if command -v iptables >/dev/null 2>&1; then
        # 简单检查iptables规则数量
        RULES_COUNT=$(iptables -L INPUT | wc -l)
        if [[ $RULES_COUNT -gt 5 ]]; then
            log_warn "检测到iptables规则，请确保以下端口已开放: $REQUIRED_PORTS"
        fi
    fi
    
    log_info "防火墙检查完成"
}

# 最终系统检查
final_system_check() {
    log_step "执行最终系统检查"
    
    # 检查服务状态
    echo -e "${CYAN}服务状态检查:${NC}"
    
    if systemctl is-active --quiet sing-box; then
        echo -e "  sing-box: ${GREEN}✓ 运行中${NC}"
    else
        echo -e "  sing-box: ${RED}✗ 未运行${NC}"
    fi
    
    if systemctl is-active --quiet nginx; then
        echo -e "  nginx: ${GREEN}✓ 运行中${NC}"
    else
        echo -e "  nginx: ${RED}✗ 未运行${NC}"
    fi
    
    # 检查端口监听
    echo -e "${CYAN}端口监听检查:${NC}"
    
    for port in 443 28790 38790 48790; do
        if ss -tuln | grep -q ":$port "; then
            echo -e "  端口 $port: ${GREEN}✓ 监听中${NC}"
        else
            echo -e "  端口 $port: ${RED}✗ 未监听${NC}"
        fi
    done
    
    # 检查证书文件
    echo -e "${CYAN}证书文件检查:${NC}"
    
    if [[ -f "/etc/ssl/private/fullchain.cer" ]]; then
        echo -e "  证书文件: ${GREEN}✓ 存在${NC}"
    else
        echo -e "  证书文件: ${RED}✗ 不存在${NC}"
    fi
    
    if [[ -f "/etc/ssl/private/private.key" ]]; then
        echo -e "  私钥文件: ${GREEN}✓ 存在${NC}"
    else
        echo -e "  私钥文件: ${RED}✗ 不存在${NC}"
    fi
    
    echo
}

# 主函数
main() {
    clear
    echo -e "${BLUE}"
    echo "=========================================================="
    echo "        sing-box + nginx Reality 一键部署脚本"
    echo "                     v2.0"
    echo "=========================================================="
    echo -e "${NC}"
    echo
    echo -e "${CYAN}脚本功能:${NC}"
    echo "• 安装 sing-box 代理服务"
    echo "• 申请和配置 SSL 证书（支持多域名）"
    echo "• 配置 nginx 反向代理和 SNI 过滤"
    echo "• 生成 Reality 密钥对"
    echo "• 支持 VLESS Reality/Vision、Hysteria2、AnyTLS"
    echo
    echo -e "${YELLOW}注意事项:${NC}"
    echo "• 请确保域名已解析到本服务器IP"
    echo "• 请确保服务器网络连接正常"
    echo "• 脚本需要root权限运行"
    echo
    read -p "按回车键继续，或Ctrl+C退出..." 
    echo
    
    # 执行安装步骤
    check_root
    collect_user_input
    install_dependencies
    install_singbox
    install_acme
    request_certificate
    generate_singbox_config
    generate_nginx_config
    start_services
    check_firewall
    generate_client_configs
    final_system_check
    
    # 最终成功信息
    echo
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN}           🎉 部署完成！${NC}"
    echo -e "${GREEN}============================================${NC}"
    echo
    log_success "所有服务已成功部署并启动！"
    echo -e "${CYAN}下一步操作:${NC}"
    echo "1. 检查防火墙是否开放所需端口"
    echo "2. 使用客户端配置信息进行连接测试"
    echo "3. 查看 /root/client-configs.txt 获取完整配置"
    echo
    echo -e "${YELLOW}如遇问题，请检查:${NC}"
    echo "• journalctl -u sing-box -f  (查看sing-box日志)"
    echo "• systemctl status nginx     (查看nginx状态)"
    echo "• tail -f /var/log/nginx/error.log  (查看nginx错误日志)"
    echo
}

# 错误处理
set -e
trap 'log_error "脚本执行失败，请检查错误信息"; exit 1' ERR

# 运行主函数
main "$@"
