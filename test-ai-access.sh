#!/usr/bin/env bash
# =============================================================================
# AI 服务 IP 可用性检测脚本 (Linux)
# 用途: 在 VPS 上直接运行，检测本机出口 IP 对主流 AI 服务的可访问性
# 依赖: curl, (可选) jq
# 用法: bash test-ai-access.sh
#       bash test-ai-access.sh -t 15      # 自定义超时
#       bash test-ai-access.sh -4         # 强制 IPv4
#       bash test-ai-access.sh -6         # 强制 IPv6
# =============================================================================

# ===== 配置 =====
TIMEOUT=10
IP_VERSION=""   # 空 / -4 / -6

# 解析参数
while getopts "t:46h" opt; do
    case "$opt" in
        t) TIMEOUT="$OPTARG" ;;
        4) IP_VERSION="-4" ;;
        6) IP_VERSION="-6" ;;
        h) sed -n '2,11p' "$0"; exit 0 ;;
        *) echo "用法: $0 [-t timeout] [-4|-6]"; exit 1 ;;
    esac
done

# 颜色
if [ -t 1 ]; then
    C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YLW=$'\033[33m'
    C_CYN=$'\033[36m'; C_MGT=$'\033[35m'; C_GRY=$'\033[90m'; C_RST=$'\033[0m'
else
    C_RED=""; C_GRN=""; C_YLW=""; C_CYN=""; C_MGT=""; C_GRY=""; C_RST=""
fi

# ===== 工具函数 =====

section() {
    echo ""
    echo "${C_CYN}============================================================${C_RST}"
    echo "${C_CYN} $1${C_RST}"
    echo "${C_CYN}============================================================${C_RST}"
}

# result <STATUS> <LABEL> [DETAIL]
result() {
    local status="$1" label="$2" detail="$3"
    local color tag
    case "$status" in
        OK)   color="$C_GRN" ;;
        FAIL) color="$C_RED" ;;
        WARN) color="$C_YLW" ;;
        *)    color="$C_GRY" ;;
    esac
    tag=$(printf "[%-4s]" "$status")
    if [ -n "$detail" ]; then
        printf "  ${color}%s${C_RST} %s ${C_GRY}- %s${C_RST}\n" "$tag" "$label" "$detail"
    else
        printf "  ${color}%s${C_RST} %s\n" "$tag" "$label"
    fi
}

# 通用 HTTP 探测，输出 "STATUSCODE|BODY"
# 用法: probe <URL> [extra curl args...]
probe() {
    local url="$1"; shift
    # -s 静默, -k 跳过证书校验防止某些 VPS 时间不准, -L 跟随重定向
    # 写入状态码到末尾，方便分离
    local out code body
    out=$(curl $IP_VERSION -sk -L --max-time "$TIMEOUT" \
              -o /tmp/.ai_probe_body.$$ \
              -w "%{http_code}" \
              "$@" "$url" 2>/dev/null)
    code="$out"
    if [ -f /tmp/.ai_probe_body.$$ ]; then
        body=$(cat /tmp/.ai_probe_body.$$ 2>/dev/null)
        rm -f /tmp/.ai_probe_body.$$
    fi
    # curl 失败时 http_code 是 000
    echo "${code:-000}|${body}"
}

# 提取状态码 / body
http_code() { echo "$1" | cut -d'|' -f1; }
http_body() { echo "$1" | cut -d'|' -f2-; }

# TCP 连通性 (用 curl --connect-timeout 测 443)
tcp_check() {
    local host="$1" port="${2:-443}"
    curl $IP_VERSION -s --connect-timeout "$TIMEOUT" \
         -o /dev/null "https://${host}:${port}" 2>/dev/null
    # 0=成功 6=DNS失败 7=连接失败 28=超时 35=TLS失败(但TCP通了，也算通)
    local rc=$?
    case "$rc" in
        0|22|35|51|52|56|60) return 0 ;;  # TCP/TLS 层通了，HTTP 层有问题不算
        *) return 1 ;;
    esac
}

# 简单 JSON 字段提取（不依赖 jq）
json_get() {
    local json="$1" key="$2"
    if command -v jq >/dev/null 2>&1; then
        echo "$json" | jq -r ".$key // empty" 2>/dev/null
    else
        # 退化方案：抓 "key":"value"
        echo "$json" | grep -oE "\"$key\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" \
            | head -1 | sed -E "s/.*:[[:space:]]*\"([^\"]*)\".*/\1/"
    fi
}

# ===== 1. 出口 IP 信息 =====

EGRESS_COUNTRY=""

get_egress_info() {
    section "出口 IP 信息"

    local resp body code
    resp=$(probe "https://ipinfo.io/json")
    code=$(http_code "$resp")
    body=$(http_body "$resp")

    # 备用源
    if [ "$code" != "200" ] || [ -z "$body" ]; then
        resp=$(probe "https://api.ip.sb/geoip")
        code=$(http_code "$resp")
        body=$(http_body "$resp")
    fi

    if [ "$code" != "200" ] || [ -z "$body" ]; then
        result FAIL "获取出口 IP" "无法访问 ipinfo.io / ip.sb"
        return
    fi

    local ip country region city org
    ip=$(json_get "$body" "ip")
    country=$(json_get "$body" "country")
    [ -z "$country" ] && country=$(json_get "$body" "country_code")
    region=$(json_get "$body" "region")
    city=$(json_get "$body" "city")
    org=$(json_get "$body" "org")
    [ -z "$org" ] && org=$(json_get "$body" "asn_organization")

    EGRESS_COUNTRY="$country"

    result INFO "出口 IP" "$ip"
    result INFO "地理位置" "$country / $region / $city"
    result INFO "ASN/ISP" "$org"

    # 各家不支持地区（公开信息，可能随时变化，仅供参考）
    local openai_blocked="CN HK RU IR KP SY CU VE BY"
    local anthropic_blocked="CN HK RU IR KP SY CU"
    local gemini_blocked="CN HK RU IR KP SY CU BY"

    check_region() {
        local svc="$1" blocked="$2"
        if echo " $blocked " | grep -q " $country "; then
            result WARN "$svc 地区限制" "$country 在不支持地区列表"
        else
            result OK "$svc 地区限制" "$country 不在限制列表"
        fi
    }
    check_region "OpenAI"    "$openai_blocked"
    check_region "Anthropic" "$anthropic_blocked"
    check_region "Gemini"    "$gemini_blocked"
}

# ===== 2. OpenAI / ChatGPT =====

test_openai() {
    section "OpenAI / ChatGPT"

    if tcp_check "api.openai.com" 443; then
        result OK "api.openai.com:443 TCP"
    else
        result FAIL "api.openai.com:443 TCP" "无法建立连接"
        return
    fi

    # ChatGPT 网站（关键：OpenAI 对不支持地区会直接 403）
    local resp code body
    resp=$(probe "https://chat.openai.com/cdn-cgi/trace")
    code=$(http_code "$resp")
    body=$(http_body "$resp")
    case "$code" in
        200)
            local loc
            loc=$(echo "$body" | grep -oE "loc=[A-Z]{2}" | head -1 | cut -d= -f2)
            result OK "chat.openai.com" "Cloudflare 节点: ${loc:-未知}"
            ;;
        403) result FAIL "chat.openai.com" "403 - 当前 IP 被拒（地区限制或风险 IP）" ;;
        000) result FAIL "chat.openai.com" "连接失败" ;;
        *)   result WARN "chat.openai.com" "状态码 $code" ;;
    esac

    # API 端点：不带 key 应返回 401 = IP 通过
    resp=$(probe "https://api.openai.com/v1/models")
    code=$(http_code "$resp")
    case "$code" in
        401) result OK   "api.openai.com 验证" "401 - IP 通过，仅缺 API Key" ;;
        403) result FAIL "api.openai.com 验证" "403 - IP 被封锁" ;;
        429) result WARN "api.openai.com 验证" "429 - IP 被限流" ;;
        000) result FAIL "api.openai.com 验证" "连接失败" ;;
        *)   result WARN "api.openai.com 验证" "状态码 $code" ;;
    esac
}

# ===== 3. Claude / Anthropic =====

test_anthropic() {
    section "Claude / Anthropic"

    if tcp_check "api.anthropic.com" 443; then
        result OK "api.anthropic.com:443 TCP"
    else
        result FAIL "api.anthropic.com:443 TCP" "无法建立连接"
        return
    fi

    # claude.ai - 用真实 UA，否则容易被 Cloudflare 当机器人拦
    local resp code
    resp=$(probe "https://claude.ai/" \
                 -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
    code=$(http_code "$resp")
    case "$code" in
        200) result OK   "claude.ai 网站" "可正常访问" ;;
        403) result FAIL "claude.ai 网站" "403 - IP 被 Cloudflare/Anthropic 拒绝" ;;
        451) result FAIL "claude.ai 网站" "451 - 法律原因不可用（地区限制）" ;;
        000) result FAIL "claude.ai 网站" "连接失败" ;;
        *)   result WARN "claude.ai 网站" "状态码 $code" ;;
    esac

    # API
    resp=$(probe "https://api.anthropic.com/v1/messages" \
                 -H "anthropic-version: 2023-06-01")
    code=$(http_code "$resp")
    case "$code" in
        401|400|405) result OK   "api.anthropic.com 验证" "$code - IP 通过，仅缺 API Key / 方法不符" ;;
        403)         result FAIL "api.anthropic.com 验证" "403 - IP 被封锁" ;;
        000)         result FAIL "api.anthropic.com 验证" "连接失败" ;;
        *)           result WARN "api.anthropic.com 验证" "状态码 $code" ;;
    esac
}

# ===== 4. Google Gemini =====

test_gemini() {
    section "Google Gemini"

    if tcp_check "generativelanguage.googleapis.com" 443; then
        result OK "generativelanguage.googleapis.com:443 TCP"
    else
        result FAIL "generativelanguage.googleapis.com:443 TCP" "无法建立连接"
        return
    fi

    # Gemini Web
    local resp code body
    resp=$(probe "https://gemini.google.com/" \
                 -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
    code=$(http_code "$resp")
    case "$code" in
        200|302) result OK   "gemini.google.com" "可正常访问" ;;
        403)     result FAIL "gemini.google.com" "403 - 当前地区不支持" ;;
        000)     result FAIL "gemini.google.com" "连接失败" ;;
        *)       result WARN "gemini.google.com" "状态码 $code" ;;
    esac

    # API - 403 需要看响应体区分原因
    resp=$(probe "https://generativelanguage.googleapis.com/v1/models")
    code=$(http_code "$resp")
    body=$(http_body "$resp")
    case "$code" in
        401)
            result OK "Gemini API 验证" "401 - IP 通过，仅缺 API Key"
            ;;
        403)
            if echo "$body" | grep -qiE "API_KEY|API key not valid|API key required"; then
                result OK   "Gemini API 验证" "403 - IP 通过，仅缺 API Key"
            elif echo "$body" | grep -qiE "location|country|region|not available|User location"; then
                result FAIL "Gemini API 验证" "403 - 地区不支持"
            else
                result WARN "Gemini API 验证" "403 - 原因不明，建议人工查响应体"
            fi
            ;;
        000) result FAIL "Gemini API 验证" "连接失败" ;;
        *)   result WARN "Gemini API 验证" "状态码 $code" ;;
    esac
}

# ===== 主流程 =====

echo ""
echo "${C_MGT}AI 服务 IP 可用性检测${C_RST}"
echo "${C_GRY}测试时间: $(date '+%Y-%m-%d %H:%M:%S')${C_RST}"
echo "${C_GRY}主机: $(hostname)${C_RST}"
[ -n "$IP_VERSION" ] && echo "${C_GRY}强制协议: ${IP_VERSION#-}${C_RST}"

# 检查 curl 是否存在
if ! command -v curl >/dev/null 2>&1; then
    echo "${C_RED}错误: 未找到 curl，请先安装 (apt install curl / yum install curl)${C_RST}"
    exit 1
fi

get_egress_info
test_openai
test_anthropic
test_gemini

section "检测完成"
echo "  ${C_GRY}说明: OK=IP 通过 / FAIL=被拒 / WARN=未预期状态${C_RST}"
echo ""
