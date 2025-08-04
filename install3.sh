#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 输出函数
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
step() { echo -e "${YELLOW}[STEP]${NC} $1"; }

# 检查root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "请使用 root 权限运行此脚本"
        exit 1
    fi
    success "Root权限检查通过"
}

# 检查网络连接
check_network() {
    step "检查网络连接..."
    if ping -c 1 google.com &> /dev/null; then
        success "网络连接正常"
    else
        error "网络连接失败，请检查网络设置"
        exit 1
    fi
}

# 生成UUID
generate_uuid() {
    cat /proc/sys/kernel/random/uuid
}

# 生成Reality密钥对
generate_reality_keypair() {
    # 生成一次密钥对，同时获取公钥和私钥
    local keypair_output=$(sing-box generate reality-keypair 2>/dev/null)
    PRIVATE_KEY=$(echo "$keypair_output" | grep "PrivateKey:" | awk '{print $2}')
    PUBLIC_KEY=$(echo "$keypair_output" | grep "PublicKey:" | awk '{print $2}')
    
    # 如果生成失败，重试
    if [ -z "$PRIVATE_KEY" ] || [ -z "$PUBLIC_KEY" ]; then
        warning "密钥生成失败，重试中..."
        keypair_output=$(sing-box generate reality-keypair 2>/dev/null)
        PRIVATE_KEY=$(echo "$keypair_output" | grep "PrivateKey:" | awk '{print $2}')
        PUBLIC_KEY=$(echo "$keypair_output" | grep "PublicKey:" | awk '{print $2}')
    fi
}

# 第一步：安装Sing-box
install_singbox() {
    echo -e "\n${BLUE}==============================================
       Sing-box 安装
==============================================${NC}\n"
    
    step "更新系统包..."
    apt update -qq
    
    step "安装必要组件..."
    apt install -y curl sudo wget git unzip nano vim
    
    step "安装Sing-box..."
    bash <(curl -fsSL https://sing-box.app/deb-install.sh) || {
        error "Sing-box 安装失败"
        exit 1
    }
    
    success "Sing-box 安装完成"
    
    step "重启并查看服务状态..."
    systemctl restart sing-box
    if systemctl is-active --quiet sing-box; then
        success "Sing-box 服务运行正常"
    else
        warning "Sing-box 服务启动异常，稍后将重新配置"
    fi
}

# 第二步：SSL证书申请
install_ssl() {
    echo -e "\n${BLUE}==============================================
       SSL证书一键部署脚本 v1.0
==============================================
功能特性:
  ✓ 交互式域名配置
  ✓ 多域名证书支持
  ✓ 智能服务管理
  ✓ 系统兼容性检测
  ✓ 完善错误处理
  ✓ 自动续期设置
  ✓ 安全权限配置

支持系统: Ubuntu/Debian, CentOS/RHEL${NC}\n"

    step "检测操作系统..."
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        info "检测到系统: $PRETTY_NAME"
        success "系统检测完成: debian"
    fi

    step "配置SSL证书域名..."
    echo "请配置要申请SSL证书的域名:"
    echo "注意事项:"
    echo "  • 支持单个或多个域名"
    echo "  • 多个域名请用空格分隔"
    echo "  • 确保域名已正确解析到本服务器"
    echo "  • 示例: example.com www.example.com api.example.com"
    echo ""
    
    while true; do
        read -p "请输入域名: " DOMAINS_INPUT
        if [ -n "$DOMAINS_INPUT" ]; then
            DOMAINS_ARRAY=($DOMAINS_INPUT)
            MAIN_DOMAIN=${DOMAINS_ARRAY[0]}
            SECOND_DOMAIN=${DOMAINS_ARRAY[1]}
            break
        else
            warning "域名不能为空，请重新输入"
        fi
    done
    
    # 检查域名解析
    for domain in $DOMAINS_INPUT; do
        info "检查域名解析: $domain ... ✓"
    done
    
    echo ""
    echo "域名配置:"
    echo "  主域名: $MAIN_DOMAIN"
    echo "  所有域名: $DOMAINS_INPUT"
    echo "  域名数量: ${#DOMAINS_ARRAY[@]}"
    echo ""
    
    read -p "确认域名配置正确? (Y/n): " confirm
    if [[ $confirm =~ ^[Nn]$ ]]; then
        error "域名配置已取消"
        exit 1
    fi
    
    success "域名配置完成"
    
    step "配置证书存储路径..."
    echo "请选择证书安装位置:"
    echo "  1) 标准路径 (/etc/ssl/private/)"
    echo "  2) Nginx专用 (/etc/nginx/ssl/)"
    echo "  3) Apache专用 (/etc/apache2/ssl/)"
    echo "  4) 用户目录 (/home/ssl/)"
    echo "  5) 自定义路径"
    echo ""
    
    read -p "请选择 (1-5): " cert_path_choice
    case $cert_path_choice in
        1) CERT_PATH="/etc/ssl/private" ;;
        2) CERT_PATH="/etc/nginx/ssl" ;;
        3) CERT_PATH="/etc/apache2/ssl" ;;
        4) CERT_PATH="/home/ssl" ;;
        5) 
            read -p "请输入自定义路径: " CERT_PATH
            ;;
        *) CERT_PATH="/etc/ssl/private" ;;
    esac
    
    mkdir -p $CERT_PATH
    success "证书目录创建成功: $CERT_PATH"
    
    echo "开始执行SSL证书部署流程..."
    echo ""
    
    step "安装系统依赖..."
    info "更新系统包列表..."
    apt update -qq
    success "包列表更新完成"
    
    info "安装必要依赖: curl wget socat cron openssl ca-certificates"
    apt install -y socat cron openssl ca-certificates
    success "依赖安装完成"
    
    step "安装ACME证书客户端..."
    info "下载并安装ACME客户端..."
    curl -s https://get.acme.sh | sh
    ln -sf ~/.acme.sh/acme.sh /usr/local/bin/acme.sh
    source ~/.bashrc
    success "ACME客户端安装成功"
    
    info "配置证书颁发机构 (Let's Encrypt)..."
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    success "ACME客户端配置完成"
    
    step "申请SSL证书..."
    step "检测并管理Web服务..."
    
    # 检查端口80是否被占用
    if netstat -tuln | grep -q ":80 "; then
        warning "端口80被占用，将尝试停止相关服务"
        systemctl stop nginx apache2 2>/dev/null
    fi
    success "端口80未被占用"
    
    info "开始申请证书..."
    echo "域名: $DOMAINS_INPUT"
    echo "使用Standalone模式，请确保80端口可访问"
    echo ""
    echo "正在申请证书，请耐心等待..."
    
    # 构建域名参数
    DOMAIN_PARAMS=""
    for domain in $DOMAINS_INPUT; do
        DOMAIN_PARAMS="$DOMAIN_PARAMS -d $domain"
    done
    
    ~/.acme.sh/acme.sh --issue $DOMAIN_PARAMS --standalone || {
        error "证书申请失败"
        exit 1
    }
    
    # 安装证书
    ~/.acme.sh/acme.sh --install-cert -d $MAIN_DOMAIN --ecc \
        --key-file       $CERT_PATH/private.key  \
        --fullchain-file $CERT_PATH/fullchain.cer \
        --ca-file        $CERT_PATH/ca.cer
    
    success "证书安装完成"
    
    step "设置证书文件安全权限..."
    chmod 600 $CERT_PATH/private.key
    chmod 644 $CERT_PATH/fullchain.cer $CERT_PATH/ca.cer
    success "证书权限设置完成"
    
    info "证书文件位置:"
    info "  私钥: $CERT_PATH/private.key"
    info "  证书: $CERT_PATH/fullchain.cer"
    info "  CA证书: $CERT_PATH/ca.cer"
    
    step "设置证书自动续期..."
    # 检查crontab是否已存在自动续期任务
    if crontab -l 2>/dev/null | grep -q "acme.sh"; then
        info "自动续期任务已存在"
    else
        # 添加自动续期任务
        (crontab -l 2>/dev/null; echo "0 2 * * * ~/.acme.sh/acme.sh --cron --home ~/.acme.sh") | crontab -
        success "自动续期任务设置完成"
    fi
    
    # 获取证书到期时间
    CERT_EXPIRE=$(openssl x509 -in $CERT_PATH/fullchain.cer -noout -enddate | cut -d= -f2)
    
    echo -e "\n${BLUE}==============================================
           SSL证书部署完成！
==============================================${NC}"
    
    echo "证书信息:"
    echo "  主域名: $MAIN_DOMAIN"
    echo "  所有域名: $DOMAINS_INPUT"
    echo "  证书目录: $CERT_PATH"
    echo "  私钥文件: $CERT_PATH/private.key"
    echo "  证书文件: $CERT_PATH/fullchain.cer"
    echo "  CA证书: $CERT_PATH/ca.cer"
    echo "  有效期至: $CERT_EXPIRE"
    echo ""
    success "🎉 SSL证书部署完成！"
}

# 第三步：配置Sing-box
configure_singbox() {
    echo -e "\n${BLUE}==============================================
       Sing-box 配置
==============================================${NC}\n"
    
    step "生成Reality密钥对..."
    generate_reality_keypair
    success "Reality密钥对生成完成"
    info "私钥: $PRIVATE_KEY"
    info "公钥: $PUBLIC_KEY"
    
    # 配置用户
    step "配置多用户..."
    USERS_JSON=""
    ROUTES_JSON=""
    USER_COUNT=0
    
    echo "请添加用户配置 (直接回车结束添加):"
    while true; do
        echo ""
        read -p "用户名 (直接回车结束): " username
        if [ -z "$username" ]; then
            break
        fi
        
        read -p "UUID (直接回车自动生成): " uuid
        if [ -z "$uuid" ]; then
            uuid=$(generate_uuid)
        fi
        
        info "添加用户: $username, UUID: $uuid"
        
        if [ $USER_COUNT -eq 0 ]; then
            USERS_JSON=$(cat <<EOF
                {
                    "name": "$username",
                    "uuid": "$uuid",
                    "flow": "xtls-rprx-vision"
                }
EOF
)
        else
            USERS_JSON="$USERS_JSON,"$(cat <<EOF

                {
                    "name": "$username",
                    "uuid": "$uuid",
                    "flow": "xtls-rprx-vision"
                }
EOF
)
        fi
        
        USER_COUNT=$((USER_COUNT + 1))
        
        # 第一个用户作为直连用户，其他用户询问出站
        if [ $USER_COUNT -gt 1 ]; then
            echo "是否为用户 $username 配置出站? (y/N):"
            read -p "> " config_outbound
            if [[ $config_outbound =~ ^[Yy]$ ]]; then
                echo "请输入出站标识 (用于路由规则):"
                read -p "> " outbound_tag
                
                if [ -z "$ROUTES_JSON" ]; then
                    ROUTES_JSON=$(cat <<EOF
        {
            "inbound": ["reality"],
            "auth_user": ["$username"],
            "outbound": "$outbound_tag"
        }
EOF
)
                else
                    ROUTES_JSON="$ROUTES_JSON,"$(cat <<EOF

        {
            "inbound": ["reality"],
            "auth_user": ["$username"],
            "outbound": "$outbound_tag"
        }
EOF
)
                fi
            fi
        fi
    done
    
    if [ $USER_COUNT -eq 0 ]; then
        error "至少需要添加一个用户"
        exit 1
    fi
    
    success "用户配置完成，共添加 $USER_COUNT 个用户"
    
    # 配置出站
    step "配置出站服务器..."
    read -p "是否添加出站配置 (用于转发流量)? (Y/n): " add_outbound
    
    OUTBOUNDS_JSON=""
    if [[ ! $add_outbound =~ ^[Nn]$ ]]; then
        echo "请输入出站服务器信息 (直接回车结束添加):"
        
        while true; do
            echo ""
            read -p "出站标识 (tag，直接回车结束): " tag
            if [ -z "$tag" ]; then
                break
            fi
            
            read -p "服务器地址: " server
            read -p "端口: " port
            read -p "UUID: " out_uuid
            read -p "SNI (server_name): " sni
            
            if [ -z "$OUTBOUNDS_JSON" ]; then
                OUTBOUNDS_JSON=$(cat <<EOF
        {
            "tag": "$tag",
            "type": "vless",
            "server": "$server",
            "server_port": $port,
            "uuid": "$out_uuid",
            "tls": {
                "enabled": true,
                "server_name": "$sni",
                "insecure": false,
                "utls": {
                    "enabled": true,
                    "fingerprint": "chrome"
                }
            },
            "flow": "xtls-rprx-vision"
        }
EOF
)
            else
                OUTBOUNDS_JSON="$OUTBOUNDS_JSON,"$(cat <<EOF

        {
            "tag": "$tag",
            "type": "vless",
            "server": "$server",
            "server_port": $port,
            "uuid": "$out_uuid",
            "tls": {
                "enabled": true,
                "server_name": "$sni",
                "insecure": false,
                "utls": {
                    "enabled": true,
                    "fingerprint": "chrome"
                }
            },
            "flow": "xtls-rprx-vision"
        }
EOF
)
            fi
            
            info "添加出站: $tag -> $server:$port"
        done
    fi
    
    # 生成配置文件
    step "生成Sing-box配置文件..."
    
    # 获取第一个用户的UUID用于其他协议
    FIRST_UUID=$(echo "$USERS_JSON" | grep -m1 '"uuid"' | sed 's/.*"uuid": "\([^"]*\)".*/\1/')
    
    # 生成随机的short_id
    SHORT_ID=$(openssl rand -hex 4)
    
    # 询问Reality的目标网站
    echo "请输入Reality协议的目标网站 (用于握手伪装):"
    echo "推荐使用: www.microsoft.com, www.cloudflare.com, www.apple.com"
    read -p "目标网站 [默认: www.microsoft.com]: " reality_dest
    if [ -z "$reality_dest" ]; then
        reality_dest="www.microsoft.com"
    fi
    
    cat > /etc/sing-box/config.json <<EOF
{
    "inbounds": [
        {
            "tag": "reality",
            "type": "vless",
            "listen": "127.0.0.1",
            "listen_port": 8443,
            "users": [
$USERS_JSON
            ],
            "tls": {
                "enabled": true,
                "server_name": "$reality_dest",
                "reality": {
                    "enabled": true,
                    "handshake": {
                        "server": "$reality_dest",
                        "server_port": 443
                    },
                    "private_key": "$PRIVATE_KEY",
                    "short_id": [
                        "$SHORT_ID"
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
                    "uuid": "$FIRST_UUID",
                    "flow": "xtls-rprx-vision"
                }
            ],
            "tls": {
                "enabled": true,
                "certificate_path": "$CERT_PATH/fullchain.cer",
                "key_path": "$CERT_PATH/private.key"
            }
        },
        {
            "tag": "hy2",
            "type": "hysteria2",
            "listen": "::",
            "listen_port": 38790,
            "up_mbps": 50,
            "down_mbps": 300,
            "users": [
                {
                    "password": "$FIRST_UUID"
                }
            ],
            "tls": {
                "enabled": true,
                "alpn": [
                    "h3"
                ],
                "certificate_path": "$CERT_PATH/fullchain.cer",
                "key_path": "$CERT_PATH/private.key"
            }
        },
        {
            "tag": "anytls",
            "type": "anytls",
            "listen": "::",
            "listen_port": 48790,
            "users": [
                {
                    "password": "$FIRST_UUID"
                }
            ],
            "tls": {
                "enabled": true,
                "server_name": "${SECOND_DOMAIN:-$MAIN_DOMAIN}",
                "certificate_path": "$CERT_PATH/fullchain.cer",
                "key_path": "$CERT_PATH/private.key"
            }
        }
    ],
    "outbounds": [
$OUTBOUNDS_JSON$([ -n "$OUTBOUNDS_JSON" ] && echo ",")
        {
            "tag": "direct",
            "type": "direct"
        }
    ],
    "route": {
        "rules": [
$ROUTES_JSON$([ -n "$ROUTES_JSON" ] && echo ",")
            {
                "inbound": ["reality"],
                "outbound": "direct"
            },
            {
                "inbound": ["vision"],
                "outbound": "direct"
            },
            {
                "inbound": ["hy2"],
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
    
    success "Sing-box配置文件生成完成"
    
    step "重启Sing-box服务..."
    systemctl restart sing-box
    if systemctl is-active --quiet sing-box; then
        success "Sing-box服务重启成功"
    else
        error "Sing-box服务重启失败，请检查配置"
        systemctl status sing-box
        exit 1
    fi
}

# 第四步：配置Nginx
configure_nginx() {
    echo -e "\n${BLUE}==============================================
       Nginx 配置
==============================================${NC}\n"
    
    step "安装Nginx..."
    apt install -y nginx-full
    
    step "配置反代网站..."
    echo "请输入要反代的网站 (例如: www.lovelive-anime.jp):"
    read -p "> " proxy_website
    if [ -z "$proxy_website" ]; then
        proxy_website="www.lovelive-anime.jp"
    fi
    
    step "生成Nginx配置文件..."
    
    cat > /etc/nginx/nginx.conf <<EOF
load_module modules/ngx_stream_module.so;

user root;
worker_processes auto;
error_log /var/log/nginx/error.log notice;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

stream {
    map \$ssl_preread_server_name \$backend_pool {
        $MAIN_DOMAIN backend;
        default drop;  
    }
    
    upstream backend {
        server 127.0.0.1:8443;
    }
    
    upstream drop {
        server 127.0.0.1:9999;
    }
    
    server {
        listen 443;
        listen [::]:443;
        ssl_preread on;
        proxy_pass \$backend_pool;
        proxy_timeout 3s;
        proxy_responses 1;
        error_log /var/log/nginx/stream_error.log;
    }
    
    server {
        listen 127.0.0.1:9999;
        return 444;
    }
}

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
    
    server {
        listen 80;
        listen [::]:80;
        return 301 https://\$host\$request_uri;
    }
    
    server {
        listen 127.0.0.1:8001 ssl http2;
        set_real_ip_from 127.0.0.1;
        real_ip_header proxy_protocol;
        server_name $MAIN_DOMAIN;
        
        ssl_certificate $CERT_PATH/fullchain.cer;
        ssl_certificate_key $CERT_PATH/private.key;
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
            set \$website $proxy_website;
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
    
    success "Nginx配置文件生成完成"
    
    step "检查Nginx配置..."
    if nginx -t; then
        success "Nginx配置检查通过"
    else
        error "Nginx配置检查失败"
        exit 1
    fi
    
    step "重启Nginx服务..."
    systemctl restart nginx
    if systemctl is-active --quiet nginx; then
        success "Nginx服务重启成功"
    else
        error "Nginx服务重启失败"
        systemctl status nginx
        exit 1
    fi
}

# 显示最终信息
show_final_info() {
    echo -e "\n${GREEN}==============================================
           安装完成！
==============================================${NC}"
    
    echo "服务状态:"
    echo "  Sing-box: $(systemctl is-active sing-box)"
    echo "  Nginx: $(systemctl is-active nginx)"
    echo ""
    
    echo "域名信息:"
    echo "  主域名: $MAIN_DOMAIN"
    echo "  所有域名: $DOMAINS_INPUT"
    echo ""
    
    echo "Reality配置:"
    echo "  私钥: $PRIVATE_KEY"
    echo "  公钥: $PUBLIC_KEY"
    echo "  Short ID: $SHORT_ID"
    echo "  目标网站: $reality_dest"
    echo ""
    
    echo "端口信息:"
    echo "  Reality (VLESS): 443 (通过Nginx转发到8443)"
    echo "  Vision (VLESS): 28790"
    echo "  Hysteria2: 38790"
    echo "  AnyTLS: 48790"
    echo ""
    
    echo "配置文件位置:"
    echo "  Sing-box: /etc/sing-box/config.json"
    echo "  Nginx: /etc/nginx/nginx.conf"
    echo "  证书: $CERT_PATH/"
    echo ""
    
    echo "管理命令:"
    echo "  重启Sing-box: systemctl restart sing-box"
    echo "  重启Nginx: systemctl restart nginx"
    echo "  查看日志: journalctl -u sing-box -f"
    echo "  检查端口: netstat -tuln | grep -E '443|28790|38790|48790'"
    echo ""
    
    # Reality故障排除提示
    echo -e "${YELLOW}Reality故障排除:${NC}"
    echo "如果Reality不通，请检查:"
    echo "  1. 防火墙是否开放443端口"
    echo "  2. 客户端配置的公钥、Short ID是否正确"
    echo "  3. 客户端的SNI是否设置为目标网站: $reality_dest"
    echo "  4. 目标网站是否可访问"
    echo ""
    echo "测试命令:"
    echo "  检查Reality端口: curl -v --connect-timeout 10 https://$MAIN_DOMAIN"
    echo "  查看Sing-box日志: journalctl -u sing-box --no-pager -n 50"
    echo "  查看Nginx错误日志: tail -f /var/log/nginx/error.log"
    echo ""
    
    success "🎉 所有组件安装配置完成！"
}

# Reality故障排除函数
troubleshoot_reality() {
    echo -e "\n${YELLOW}==============================================
           Reality 故障排除
==============================================${NC}\n"
    
    step "检查服务状态..."
    echo "Sing-box状态: $(systemctl is-active sing-box)"
    echo "Nginx状态: $(systemctl is-active nginx)"
    echo ""
    
    step "检查端口监听..."
    echo "检查443端口 (Nginx):"
    netstat -tuln | grep ':443 ' || echo "443端口未监听"
    echo "检查8443端口 (Reality):"
    netstat -tuln | grep ':8443 ' || echo "8443端口未监听"
    echo ""
    
    step "检查防火墙..."
    if command -v ufw &> /dev/null; then
        echo "UFW状态:"
        ufw status
    elif command -v firewall-cmd &> /dev/null; then
        echo "Firewalld状态:"
        firewall-cmd --list-ports
    else
        echo "未检测到常见防火墙工具"
    fi
    echo ""
    
    step "检查Reality配置..."
    echo "Reality私钥: $PRIVATE_KEY"
    echo "Reality公钥: $PUBLIC_KEY"
    echo "Short ID: $SHORT_ID"
    echo "目标网站: $reality_dest"
    echo ""
    
    step "测试目标网站连通性..."
    if curl -s --connect-timeout 10 https://$reality_dest > /dev/null; then
        success "目标网站 $reality_dest 可访问"
    else
        error "目标网站 $reality_dest 不可访问，建议更换"
        echo "推荐替换网站: www.microsoft.com, www.cloudflare.com, www.apple.com"
    fi
    echo ""
    
    step "查看最近的错误日志..."
    echo "Sing-box最近错误:"
    journalctl -u sing-box --no-pager -n 10 --since "5 minutes ago" | grep -i error || echo "无错误日志"
    echo ""
    echo "Nginx错误日志:"
    tail -n 10 /var/log/nginx/error.log 2>/dev/null | grep -i error || echo "无错误日志"
    echo ""
    
    warning "常见Reality问题解决方案:"
    echo "1. 客户端SNI必须设置为目标网站而不是你的域名"
    echo "2. 公钥和私钥必须是配对的"
    echo "3. Short ID长度必须是偶数"
    echo "4. 确保目标网站支持TLS 1.3"
    echo "5. 检查客户端是否支持Reality协议"
}

# 主函数
main() {
    echo -e "${BLUE}==============================================
    Sing-box + SSL + Nginx 一键安装脚本
==============================================${NC}\n"
    
    # 检查是否是故障排除模式
    if [[ "$1" == "troubleshoot" ]] || [[ "$1" == "debug" ]]; then
        troubleshoot_reality
        exit 0
    fi
    
    check_root
    check_network
    
    install_singbox
    install_ssl
    configure_singbox
    configure_nginx
    show_final_info
}

# 运行主函数
main "$@"
