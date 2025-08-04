#!/bin/bash

set -e

echo "=================================================="
echo "        sing-box + nginx 一键部署脚本"
echo "=================================================="

# 1. 安装基本组件和 sing-box
echo "[STEP] 安装必要组件..."
apt update && apt install -y curl sudo wget git unzip nano vim socat cron nginx-full

echo "[STEP] 安装 sing-box..."
bash <(curl -fsSL https://sing-box.app/deb-install.sh)

# 2. 配置 SSL 证书
echo
echo "[STEP] 配置 SSL证书域名..."
read -p "请输入域名（支持多个，用空格分隔）: " DOMAIN_LIST
for DOMAIN in $DOMAIN_LIST; do
  echo "[INFO] 正在为 $DOMAIN 申请证书..."
done

curl https://get.acme.sh | sh
source ~/.bashrc
~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
~/.acme.sh/acme.sh --issue --standalone -d $DOMAIN_LIST

mkdir -p /etc/ssl/private
~/.acme.sh/acme.sh --install-cert -d $(echo $DOMAIN_LIST | awk '{print $1}') --ecc \
--key-file /etc/ssl/private/private.key \
--fullchain-file /etc/ssl/private/fullchain.cer \
--ca-file /etc/ssl/private/ca.cer

echo
echo "=============================================="
echo "           SSL证书部署完成！"
echo "=============================================="
echo "证书信息:"
echo "  主域名: $(echo $DOMAIN_LIST | awk '{print $1}')"
echo "  所有域名: $DOMAIN_LIST"
echo "  证书目录: /etc/ssl/private"
echo "  私钥文件: /etc/ssl/private/private.key"
echo "  证书文件: /etc/ssl/private/fullchain.cer"
echo "  CA证书: /etc/ssl/private/ca.cer"
echo

# 3. 生成 sing-box 配置
echo "[STEP] 配置 sing-box..."
read -p "请输入Reality主域名（与上面一致）: " REALITY_DOMAIN
read -p "请输入AnyTLS域名: " ANYTLS_DOMAIN
read -p "请输入反代网站 [默认: www.lovelive-anime.jp]: " PROXY_SITE
PROXY_SITE=${PROXY_SITE:-www.lovelive-anime.jp}

read -p "请输入Reality私钥 [留空自动生成]: " REALITY_PRIV_KEY
if [ -z "$REALITY_PRIV_KEY" ]; then
  KEY_PAIR=$(sing-box generate reality-keypair)
  REALITY_PRIV_KEY=$(echo "$KEY_PAIR" | grep PrivateKey | awk '{print $2}')
  REALITY_PUB_KEY=$(echo "$KEY_PAIR" | grep PublicKey | awk '{print $2}')
  echo "[INFO] 已生成Reality密钥对:"
  echo "  PublicKey: $REALITY_PUB_KEY"
  echo "  PrivateKey: $REALITY_PRIV_KEY"
else
  echo "[WARN] 你输入了自定义私钥，未生成公钥。"
fi

read -p "请输入Reality短ID [留空自动生成]: " SHORT_ID
SHORT_ID=${SHORT_ID:-$(openssl rand -hex 3)}
echo "[INFO] 使用短ID: $SHORT_ID"

# 添加多用户
echo
echo "[STEP] 添加 Reality 多用户 (回车跳过)"
USERS_JSON=""
while true; do
  read -p "请输入用户名 [回车跳过]: " NAME
  [ -z "$NAME" ] && break
  read -p "请输入UUID（为空自动生成）: " UUID
  UUID=${UUID:-$(uuidgen)}
  USERS_JSON="$USERS_JSON{\"name\":\"$NAME\",\"uuid\":\"$UUID\",\"flow\":\"xtls-rprx-vision\"},"
done
USERS_JSON="[${USERS_JSON%,}]"

# 添加出站
echo
read -p "[INFO] 是否添加出站配置？(用于转发流量) y/n [默认: y]: " ADD_OUT
ADD_OUT=${ADD_OUT:-y}

OUTBOUND_JSON=""
if [[ "$ADD_OUT" == "y" ]]; then
  while true; do
    read -p "请输入出站服务器链接 (sing-box格式)，回车结束: " OUTLINK
    [ -z "$OUTLINK" ] && break
    TAG=$(echo $OUTLINK | sed 's/.*#//;s/%28/(/;s/%29/)/')
    OUTBOUND=$(sing-box convert $OUTLINK --outbound --tag "$TAG")
    OUTBOUND_JSON="$OUTBOUND_JSON$OUTBOUND,"
  done
  OUTBOUND_JSON="[${OUTBOUND_JSON%,}]"
else
  OUTBOUND_JSON="[ {\"tag\": \"direct\", \"type\": \"direct\"} ]"
fi

# 生成配置文件（config.json）
echo "[INFO] 正在生成配置文件..."
# → 这里我会根据你之前提供的模板填入变量，包括 $REALITY_PRIV_KEY、$SHORT_ID、$USERS_JSON、$OUTBOUND_JSON 等
# ...

# 4. 配置 Nginx（SNI 分流 + 反代）
echo "[STEP] 配置 Nginx..."
# → 生成 nginx.conf，使用 $REALITY_DOMAIN 和 $PROXY_SITE

# 5. 最终启动服务
echo "[STEP] 重启服务..."
systemctl restart sing-box
systemctl enable sing-box
systemctl restart nginx
systemctl enable nginx

echo
echo "🎉 部署完成！"
