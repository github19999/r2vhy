#!/bin/bash

#====================================================================================
#
#        sing-box + Nginx 全功能一键部署脚本
#
#        作者: Gemini
#
#        描述: 本脚本用于在 Debian/Ubuntu 系统上自动化部署 sing-box 和 Nginx，
#              实现多用户 Reality、Vision、Hysteria2 等协议，并支持流量转发。
#
#====================================================================================

# --- 全局变量和颜色定义 ---
# 颜色代码
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置文件路径
SING_BOX_CONFIG_PATH="/etc/sing-box/config.json"
NGINX_CONFIG_PATH="/etc/nginx/nginx.conf"
SSL_CERT_PATH="/etc/ssl/private/fullchain.cer"
SSL_KEY_PATH="/etc/ssl/private/private.key"

# --- 工具函数 ---

# 日志打印
log_info() {
    echo -e "${GREEN}[信息] $1${NC}"
}

log_warn() {
    echo -e "${YELLOW}[警告] $1${NC}"
}

log_error() {
    echo -e "${RED}[错误] $1${NC}"
}

# 检查命令是否成功执行
check_success() {
    if [ $? -ne 0 ]; then
        log_error "$1 失败，脚本终止。"
        exit 1
    fi
}

# --- 核心功能函数 ---

# 1. 环境准备和依赖安装
install_dependencies() {
    log_info "开始更新软件包列表并安装必要组件..."
    apt update
    apt install -y curl sudo wget git unzip nano vim socat cron nginx-full
    check_success "依赖项安装"
    log_info "必要组件安装完成。"
}

# 2. 安装 sing-box
install_singbox() {
    log_info "开始安装 sing-box..."
    bash <(curl -fsSL https://sing-box.app/deb-install.sh)
    check_success "sing-box 安装"
    # 确保服务停止，以便后续配置
    systemctl stop sing-box
    log_info "sing-box 安装成功。"
}

# 3. 安装 acme.sh 并申请证书
install_acme_and_issue_cert() {
    log_info "开始安装 acme.sh 证书申请工具..."
    if ! command -v acme.sh &> /dev/null; then
        curl https://get.acme.sh | sh
        check_success "acme.sh 安装"
        ln -s "/root/.acme.sh/acme.sh" /usr/local/bin/acme.sh
        acme.sh --set-default-ca --server letsencrypt
    else
        log_warn "acme.sh 已安装，跳过安装步骤。"
    fi

    echo -e "\n=================================================="
    echo -e "         ${BLUE}STEP 1: 配置SSL证书域名${NC}"
    echo -e "=================================================="
    echo "注意事项:"
    echo "  •  请输入一个或多个域名，用空格分隔。"
    echo "  •  第一个域名将作为主域名 (用于 Reality SNI 和 Nginx)。"
    echo "  •  请确保所有域名都已正确解析到本服务器的 IP 地址。"
    echo "  •  示例: domain.com www.domain.com sub.domain.com"
    echo ""
    read -rp "请输入您的域名: " DOMAIN_INPUT
    
    if [ -z "$DOMAIN_INPUT" ]; then
        log_error "域名输入不能为空！"
        exit 1
    fi
    
    # 将输入的域名字符串转换为数组
    IFS=' ' read -r -a DOMAINS <<< "$DOMAIN_INPUT"
    PRIMARY_DOMAIN=${DOMAINS[0]}
    
    # 构建 acme.sh 命令
    ACME_CMD="acme.sh --issue --standalone"
    for domain in "${DOMAINS[@]}"; do
        ACME_CMD+=" -d $domain"
    done
    
    log_info "正在为域名 [${DOMAINS[*]}] 申请SSL证书..."
    log_info "执行命令: ${ACME_CMD}"
    eval ${ACME_CMD}
    check_success "SSL证书申请"
    
    log_info "正在安装证书到指定目录..."
    mkdir -p /etc/ssl/private
    acme.sh --install-cert -d ${PRIMARY_DOMAIN} --ecc \
        --key-file       ${SSL_KEY_PATH}  \
        --fullchain-file ${SSL_CERT_PATH}
    check_success "SSL证书安装"
    
    # 获取证书有效期
    cert_info=$(openssl x509 -in ${SSL_CERT_PATH} -noout -enddate -subject)
    expiry_date=$(echo "$cert_info" | grep 'notAfter' | awk -F'=' '{print $2}')

    echo -e "\n==============================================="
    echo -e "           ${GREEN}SSL证书部署完成！${NC}"
    echo -e "==============================================="
    echo -e "证书信息:"
    echo -e "  ${BLUE}主域名:${NC} ${PRIMARY_DOMAIN}"
    echo -e "  ${BLUE}所有域名:${NC} ${DOMAINS[*]}"
    echo -e "  ${BLUE}证书目录:${NC} /etc/ssl/private"
    echo -e "  ${BLUE}私钥文件:${NC} ${SSL_KEY_PATH}"
    echo -e "  ${BLUE}证书文件:${NC} ${SSL_CERT_PATH}"
    echo -e "  ${BLUE}有效期至:${NC} ${expiry_date}"
    echo ""
    echo -e "管理命令:"
    echo -e "  ${YELLOW}查看证书:${NC} acme.sh --list"
    echo -e "  ${YELLOW}手动续期:${NC} acme.sh --renew -d ${PRIMARY_DOMAIN} --force"
    echo ""
    log_info "🎉 SSL证书已成功部署并设置自动续期。"
    
    # 保存域名信息用于后续步骤
    SECOND_DOMAIN=${DOMAINS[1]:-$PRIMARY_DOMAIN} # 如果只提供一个域名，则第二个域名也用主域名
}

# 4. 配置 sing-box
configure_singbox() {
    log_info "开始配置 sing-box..."
    
    # --- 收集用户信息 ---
    echo -e "\n=================================================="
    echo -e "        ${BLUE}STEP 2: 配置 sing-box 核心参数${NC}"
    echo -e "=================================================="
    read -rp "请输入用于伪装的反代网站 [默认: www.lovelive-anime.jp]: " PROXY_WEBSITE
    [ -z "${PROXY_WEBSITE}" ] && PROXY_WEBSITE="www.lovelive-anime.jp"

    log_info "正在生成 Reality 密钥对和相关参数..."
    REALITY_KEY_PAIR=$(sing-box generate reality-keypair)
    REALITY_PRIVATE_KEY=$(echo "$REALITY_KEY_PAIR" | awk '/PrivateKey/ {print $2}')
    REALITY_PUBLIC_KEY=$(echo "$REALITY_KEY_PAIR" | awk '/PublicKey/ {print $2}')
    REALITY_SHORT_ID=$(openssl rand -hex 6)
    MAIN_UUID=$(sing-box generate uuid)

    echo -e "${GREEN}Reality 私钥已生成: ${NC}${REALITY_PRIVATE_KEY}"
    echo -e "${GREEN}Reality 公钥已生成: ${NC}${REALITY_PUBLIC_KEY}"
    echo -e "${GREEN}Reality ShortID 已生成: ${NC}${REALITY_SHORT_ID}"
    echo -e "${GREEN}主用户 UUID 已生成: ${NC}${MAIN_UUID}"

    # --- 收集多用户和出站信息 ---
    USERS_JSON=""
    OUTBOUNDS_JSON=""
    ROUTING_RULES_JSON=""
    CLIENT_CONFIGS=""

    # 添加默认的直连用户
    USERS_JSON+="{ \"name\": \"direct-user\", \"uuid\": \"${MAIN_UUID}\", \"flow\": \"xtls-rprx-vision\" }"

    read -rp "是否需要添加额外的转发用户 (通过出站服务器转发流量)? [y/N]: " ADD_OUTBOUNDS
    if [[ "$ADD_OUTBOUNDS" =~ ^[yY]$ ]]; then
        log_info "进入转发配置模式。请逐一输入出站服务器的 VLESS 链接。"
        log_warn "链接格式必须为: vless://uuid@domain:port?params#tag_name"
        log_warn "每输入一个链接，脚本将自动创建一个同名的入站用户与其对应。"
        log_warn "输入完成后，直接按 Enter 键结束添加。"

        while true; do
            echo ""
            read -rp "请输入 VLESS 出站链接 (或直接回车完成): " VLESS_LINK
            [ -z "$VLESS_LINK" ] && break

            # 解析 VLESS 链接
            if [[ $VLESS_LINK =~ vless://([^@]+)@([^:]+):([0-9]+)\?([^#]+)#(.+) ]]; then
                OUT_UUID=${BASH_REMATCH[1]}
                OUT_SERVER=${BASH_REMATCH[2]}
                OUT_PORT=${BASH_REMATCH[3]}
                OUT_PARAMS=${BASH_REMATCH[4]}
                OUT_TAG_RAW=${BASH_REMATCH[5]}
                
                # URL 解码 TAG
                OUT_TAG=$(printf '%b' "${OUT_TAG_RAW//%/\\x}")

                # 从参数中提取 flow 和 sni
                OUT_FLOW=$(echo $OUT_PARAMS | sed -n 's/.*flow=\([^&]*\).*/\1/p')
                OUT_SNI=$(echo $OUT_PARAMS | sed -n 's/.*sni=\([^&]*\).*/\1/p')
                [ -z "$OUT_SNI" ] && OUT_SNI=$OUT_SERVER
                
                log_info "成功解析出站: [${OUT_TAG}]"
                
                # 为此出站创建一个新的入站用户
                USER_UUID=$(sing-box generate uuid)
                USERS_JSON+=",{ \"name\": \"${OUT_TAG}\", \"uuid\": \"${USER_UUID}\", \"flow\": \"xtls-rprx-vision\" }"
                
                # 创建出站配置
                CURRENT_OUTBOUND="{
                    \"tag\": \"${OUT_TAG}\",
                    \"type\": \"vless\",
                    \"server\": \"${OUT_SERVER}\",
                    \"server_port\": ${OUT_PORT},
                    \"uuid\": \"${OUT_UUID}\",
                    \"flow\": \"${OUT_FLOW}\",
                    \"tls\": {
                        \"enabled\": true,
                        \"server_name\": \"${OUT_SNI}\",
                        \"utls\": { \"enabled\": true, \"fingerprint\": \"chrome\" }
                    }
                }"
                OUTBOUNDS_JSON+=",${CURRENT_OUTBOUND}"

                # 创建路由规则
                CURRENT_RULE="{ \"inbound\": [\"reality-in\"], \"auth_user\": [\"${OUT_TAG}\"], \"outbound\": \"${OUT_TAG}\" }"
                ROUTING_RULES_JSON+=",${CURRENT_RULE}"
                
                # 生成客户端配置链接
                CLIENT_VLESS_LINK="vless://${USER_UUID}@${PRIMARY_DOMAIN}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${PROXY_WEBSITE}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}#${OUT_TAG}"
                CLIENT_CONFIGS+="\n客户端配置 (${OUT_TAG}):\n${YELLOW}${CLIENT_VLESS_LINK}${NC}\n"

            else
                log_error "VLESS 链接格式无效，请检查后重新输入。"
            fi
        done
    fi

    # --- 生成 config.json ---
    log_info "正在生成 sing-box 配置文件..."
    
    cat > ${SING_BOX_CONFIG_PATH} <<EOF
{
    "log": {
        "level": "info",
        "timestamp": true
    },
    "inbounds": [
        {
            "tag": "reality-in",
            "type": "vless",
            "listen": "127.0.0.1",
            "listen_port": 8443,
            "users": [
                ${USERS_JSON}
            ],
            "tls": {
                "enabled": true,
                "server_name": "${PRIMARY_DOMAIN}",
                "reality": {
                    "enabled": true,
                    "handshake": { "server": "127.0.0.1", "server_port": 8001 },
                    "private_key": "${REALITY_PRIVATE_KEY}",
                    "short_id": [ "${REALITY_SHORT_ID}" ]
                }
            }
        },
        {
            "tag": "vision-in",
            "type": "vless",
            "listen": "::",
            "listen_port": 28790,
            "users": [ { "uuid": "${MAIN_UUID}", "flow": "xtls-rprx-vision" } ],
            "tls": { "enabled": true, "certificate_path": "${SSL_CERT_PATH}", "key_path": "${SSL_KEY_PATH}" }
        },
        {
            "tag": "hysteria2-in",
            "type": "hysteria2",
            "listen": "::",
            "listen_port": 38790,
            "up_mbps": 50,
            "down_mbps": 300,
            "users": [ { "password": "${MAIN_UUID}" } ],
            "tls": { "enabled": true, "alpn": ["h3"], "certificate_path": "${SSL_CERT_PATH}", "key_path": "${SSL_KEY_PATH}" }
        },
        {
            "tag": "anytls-in",
            "type": "tuic",
            "listen": "::",
            "listen_port": 48790,
            "users": [ { "uuid": "${MAIN_UUID}", "password": "${MAIN_UUID}" } ],
            "tls": { "enabled": true, "server_name": "${SECOND_DOMAIN}", "certificate_path": "${SSL_CERT_PATH}", "key_path": "${SSL_KEY_PATH}" }
        }
    ],
    "outbounds": [
        { "tag": "direct", "type": "direct" }
        ${OUTBOUNDS_JSON}
    ],
    "route": {
        "rules": [
            { "inbound": ["reality-in"], "auth_user": ["direct-user"], "outbound": "direct" }
            ${ROUTING_RULES_JSON},
            { "inbound": ["vision-in", "hysteria2-in", "anytls-in"], "outbound": "direct" },
            { "ip_is_private": true, "outbound": "direct" }
        ]
    }
}
EOF
    check_success "sing-box 配置文件生成"
    log_info "sing-box 配置文件 ${SING_BOX_CONFIG_PATH} 已创建。"
}

# 5. 配置 Nginx
configure_nginx() {
    log_info "开始配置 Nginx..."

    cat > ${NGINX_CONFIG_PATH} <<EOF
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
        ${PRIMARY_DOMAIN} backend;
        default drop;
    }
    
    upstream backend {
        server 127.0.0.1:8443;
    }
    
    upstream drop {
        server 127.0.0.1:9999; # 一个不存在或拒绝连接的端口
    }

    server {
        listen 443;
        listen [::]:443;
        ssl_preread on;
        proxy_pass \$backend_pool;
        proxy_timeout 3s;
    }
    
    server {
        listen 127.0.0.1:9999;
        return 444; # Nginx 特有代码，直接关闭连接
    }
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    
    sendfile on;
    keepalive_timeout 65;
    
    # 强制跳转到 HTTPS
    server {
        listen 80;
        listen [::]:80;
        server_name _;
        return 301 https://\$host\$request_uri;
    }

    # 处理 Reality 回落的伪装网站
    server {
        listen 127.0.0.1:8001 ssl http2;
        server_name ${PRIMARY_DOMAIN};
        
        ssl_certificate ${SSL_CERT_PATH};
        ssl_certificate_key ${SSL_KEY_PATH};
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
        
        location / {
            proxy_pass https://${PROXY_WEBSITE};
            proxy_set_header Host ${PROXY_WEBSITE};
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
            proxy_ssl_server_name on;
        }
    }
}
EOF
    check_success "Nginx 配置文件生成"
    log_info "Nginx 配置文件 ${NGINX_CONFIG_PATH} 已创建。"
}

# 6. 启动并检查服务
start_services() {
    log_info "正在检查 Nginx 配置文件语法..."
    nginx -t
    check_success "Nginx 配置文件语法检查"
    
    log_info "正在启动并设置 sing-box 和 Nginx 开机自启..."
    systemctl restart sing-box
    systemctl enable sing-box
    systemctl restart nginx
    systemctl enable nginx
    
    # 等待一小会儿，让服务有时间启动
    sleep 3
    
    log_info "检查服务状态:"
    singbox_status=$(systemctl is-active sing-box)
    nginx_status=$(systemctl is-active nginx)
    
    if [ "$singbox_status" = "active" ]; then
        log_info "sing-box 服务正在运行。"
    else
        log_error "sing-box 服务启动失败，请使用 'journalctl -u sing-box --no-pager -l' 命令查看日志。"
    fi
    
    if [ "$nginx_status" = "active" ]; then
        log_info "Nginx 服务正在运行。"
    else
        log_error "Nginx 服务启动失败，请使用 'journalctl -u nginx --no-pager -l' 命令查看日志。"
    fi
}

# 7. 显示最终配置信息
display_summary() {
    # 默认直连用户的客户端配置
    DIRECT_VLESS_LINK="vless://${MAIN_UUID}@${PRIMARY_DOMAIN}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${PROXY_WEBSITE}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}#${PRIMARY_DOMAIN}-direct"
    
    echo -e "\n\n========================================================================="
    echo -e "              🎉 ${GREEN}祝贺您！Sing-box + Nginx 已全部署完成！${NC} 🎉"
    echo -e "=========================================================================\n"
    echo -e "${BLUE}---------- [ Reality 核心配置 ] ----------${NC}"
    echo -e "协议: ${YELLOW}VLESS + Reality${NC}"
    echo -e "地址: ${YELLOW}${PRIMARY_DOMAIN}${NC}"
    echo -e "端口: ${YELLOW}443${NC}"
    echo -e "公钥 (PublicKey): ${YELLOW}${REALITY_PUBLIC_KEY}${NC}"
    echo -e "短ID (ShortID): ${YELLOW}${REALITY_SHORT_ID}${NC}"
    echo -e "指纹 (Fingerprint): ${YELLOW}chrome${NC}"
    echo -e "流控 (Flow): ${YELLOW}xtls-rprx-vision${NC}"
    echo -e "目标网站 (SNI): ${YELLOW}${PROXY_WEBSITE}${NC}"
    
    echo -e "\n${BLUE}---------- [ Reality 用户链接 ] ----------${NC}"
    echo -e "默认直连用户 (${PRIMARY_DOMAIN}-direct):"
    echo -e "${YELLOW}${DIRECT_VLESS_LINK}${NC}"
    if [ -n "$CLIENT_CONFIGS" ]; then
        echo -e "${CLIENT_CONFIGS}"
    fi

    echo -e "\n${BLUE}---------- [ 其他协议配置 ] ----------${NC}"
    echo -e "协议: ${YELLOW}VLESS + Vision${NC}"
    echo -e "地址: ${YELLOW}${PRIMARY_DOMAIN}${NC}"
    echo -e "端口: ${YELLOW}28790${NC}"
    echo -e "UUID: ${YELLOW}${MAIN_UUID}${NC}"
    echo -e "流控: ${YELLOW}xtls-rprx-vision${NC}"
    
    echo -e "\n协议: ${YELLOW}Hysteria2${NC}"
    echo -e "地址: ${YELLOW}${PRIMARY_DOMAIN}:38790${NC}"
    echo -e "密码: ${YELLOW}${MAIN_UUID}${NC}"
    echo -e "SNI: ${YELLOW}${PRIMARY_DOMAIN}${NC}"
    
    echo -e "\n协议: ${YELLOW}TUIC (v5)${NC}"
    echo -e "地址: ${YELLOW}${SECOND_DOMAIN}:48790${NC}"
    echo -e "UUID: ${YELLOW}${MAIN_UUID}${NC}"
    echo -e "密码: ${YELLOW}${MAIN_UUID}${NC}"
    echo -e "SNI: ${YELLOW}${SECOND_DOMAIN}${NC}"

    echo -e "\n========================================================================="
    echo -e "提示: 请使用支持相应协议的客户端导入以上链接或手动配置。"
    echo -e "=========================================================================\n"
}


# --- 主函数 ---
main() {
    # 检查是否以 root 身份运行
    if [ "$(id -u)" -ne 0 ]; then
        log_error "此脚本需要以 root 权限运行。请使用 'sudo -i' 或 'sudo su' 命令切换到 root 用户后重试。"
        exit 1
    fi

    clear
    echo -e "=================================================="
    echo -e "      欢迎使用 sing-box + Nginx 自动化部署脚本"
    echo -e "=================================================="
    echo -e "本脚本将引导您完成所有安装和配置步骤。"
    echo -e "准备开始安装...\n"
    
    # 执行所有步骤
    install_dependencies
    install_singbox
    install_acme_and_issue_cert
    configure_singbox
    configure_nginx
    start_services
    display_summary
}

# 脚本入口
main
