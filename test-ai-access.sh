#!/usr/bin/env bash
# =============================================================================
# AI 服务 IP 可用性检测 v2 (Linux)
# 新增: 针对 claude.ai 的 Cloudflare 风控深度检测
# 依赖: curl
# 用法: bash test-ai-access.sh [-t 超时秒] [-4|-6] [-v 详细输出]
# =============================================================================

TIMEOUT=10
IP_VERSION=""
VERBOSE=0

while getopts "t:46vh" opt; do
    case "$opt" in
        t) TIMEOUT="$OPTARG" ;;
        4) IP_VERSION="-4" ;;
        6) IP_VERSION="-6" ;;
        v) VERBOSE=1 ;;
        h) sed -n '2,9p' "$0"; exit 0 ;;
        *) echo "用法: $0 [-t timeout] [-4|-6] [-v]"; exit 1 ;;
    esac
done

if [ -t 1 ]; then
    C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YLW=$'\033[33m'
    C_CYN=$'\033[36m'; C_MGT=$'\033[35m'; C_GRY=$'\033[90m'; C_RST=$'\033[0m'
else
    C_RED=""; C_GRN=""; C_YLW=""; C_CYN=""; C_MGT=""; C_GRY=""; C_RST=""
fi

section() {
    echo ""
    echo "${C_CYN}============================================================${C_RST}"
    echo "${C_CYN} $1${C_RST}"
    echo "${C_CYN}============================================================${C_RST}"
}

result() {
    local status="$1" label="$2" detail="$3" color tag
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

probe() {
    local url="$1"; shift
    local tmp=/tmp/.ai_probe_body.$$
    local code
    code=$(curl $IP_VERSION -sk -L --max-time "$TIMEOUT" \
                -o "$tmp" -w "%{http_code}" \
                "$@" "$url" 2>/dev/null)
    local body=""
    [ -f "$tmp" ] && { body=$(cat "$tmp"); rm -f "$tmp"; }
    echo "${code:-000}|${body}"
}

probe_full() {
    local url="$1"; shift
    local btmp=/tmp/.ai_body.$$ htmp=/tmp/.ai_head.$$
    local code
    code=$(curl $IP_VERSION -sk -L --max-time "$TIMEOUT" \
                -D "$htmp" -o "$btmp" -w "%{http_code}" \
                "$@" "$url" 2>/dev/null)
    local body="" headers=""
    [ -f "$btmp" ] && { body=$(cat "$btmp"); rm -f "$btmp"; }
    [ -f "$htmp" ] && { headers=$(cat "$htmp"); rm -f "$htmp"; }
    printf "%s\x1e%s\x1e%s" "${code:-000}" "$headers" "$body"
}

http_code() { echo "$1" | cut -d'|' -f1; }
http_body() { echo "$1" | cut -d'|' -f2-; }

tcp_check() {
    curl $IP_VERSION -s --connect-timeout "$TIMEOUT" \
         -o /dev/null "https://$1:${2:-443}" 2>/dev/null
    case $? in
        0|22|35|51|52|56|60) return 0 ;;
        *) return 1 ;;
    esac
}

json_get() {
    local json="$1" key="$2"
    if command -v jq >/dev/null 2>&1; then
        echo "$json" | jq -r ".$key // empty" 2>/dev/null
    else
        echo "$json" | grep -oE "\"$key\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" \
            | head -1 | sed -E "s/.*:[[:space:]]*\"([^\"]*)\".*/\1/"
    fi
}

BROWSER_UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
BROWSER_HEADERS=(
    -H "User-Agent: $BROWSER_UA"
    -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
    -H "Accept-Language: en-US,en;q=0.9"
    -H "Sec-Fetch-Dest: document"
    -H "Sec-Fetch-Mode: navigate"
    -H "Sec-Fetch-Site: none"
    -H "Sec-Fetch-User: ?1"
    -H "Upgrade-Insecure-Requests: 1"
    --compressed
)

EGRESS_COUNTRY=""

get_egress_info() {
    section "出口 IP 信息"

    local resp body code
    resp=$(probe "https://ipinfo.io/json")
    code=$(http_code "$resp"); body=$(http_body "$resp")

    if [ "$code" != "200" ] || [ -z "$body" ]; then
        resp=$(probe "https://api.ip.sb/geoip")
        code=$(http_code "$resp"); body=$(http_body "$resp")
    fi

    if [ "$code" != "200" ] || [ -z "$body" ]; then
        result FAIL "获取出口 IP" "IP 信息源不可达"
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

    if echo "$org" | grep -qiE "amazon|aws|google|microsoft|azure|oracle|digitalocean|linode|vultr|hetzner|ovh|contabo|leaseweb|choopa|gcore|alibaba|tencent"; then
        result WARN "ASN 类型" "数据中心 IP - 易被 Cloudflare 风控"
    else
        result OK "ASN 类型" "非典型数据中心 ASN"
    fi
}

test_openai() {
    section "OpenAI / ChatGPT"

    if ! tcp_check "api.openai.com"; then
        result FAIL "api.openai.com:443 TCP" "无法建立连接"; return
    fi
    result OK "api.openai.com:443 TCP"

    local resp code body
    resp=$(probe "https://chat.openai.com/cdn-cgi/trace" "${BROWSER_HEADERS[@]}")
    code=$(http_code "$resp"); body=$(http_body "$resp")
    case "$code" in
        200)
            local loc; loc=$(echo "$body" | grep -oE "loc=[A-Z]{2}" | head -1 | cut -d= -f2)
            result OK "chat.openai.com" "CF 节点: ${loc:-未知}"
            ;;
        403) result FAIL "chat.openai.com" "403 - IP 被拒（地区或风险）" ;;
        000) result FAIL "chat.openai.com" "连接失败" ;;
        *)   result WARN "chat.openai.com" "状态码 $code" ;;
    esac

    resp=$(probe "https://api.openai.com/v1/models")
    code=$(http_code "$resp")
    case "$code" in
        401) result OK   "api.openai.com 验证" "401 - IP 通过，仅缺 API Key" ;;
        403) result FAIL "api.openai.com 验证" "403 - IP 被封锁" ;;
        429) result WARN "api.openai.com 验证" "429 - 被限流" ;;
        000) result FAIL "api.openai.com 验证" "连接失败" ;;
        *)   result WARN "api.openai.com 验证" "状态码 $code" ;;
    esac
}

test_anthropic() {
    section "Claude / Anthropic"

    if ! tcp_check "api.anthropic.com"; then
        result FAIL "api.anthropic.com:443 TCP" "无法建立连接"
    else
        result OK "api.anthropic.com:443 TCP"
        local r c
        r=$(probe "https://api.anthropic.com/v1/messages" -H "anthropic-version: 2023-06-01")
        c=$(http_code "$r")
        case "$c" in
            401|400|405) result OK   "api.anthropic.com 验证" "$c - IP 通过，仅缺 API Key" ;;
            403)         result FAIL "api.anthropic.com 验证" "403 - IP 被封锁" ;;
            000)         result FAIL "api.anthropic.com 验证" "连接失败" ;;
            *)           result WARN "api.anthropic.com 验证" "状态码 $c" ;;
        esac
    fi

    if ! tcp_check "claude.ai"; then
        result FAIL "claude.ai:443 TCP" "无法建立连接"; return
    fi
    result OK "claude.ai:443 TCP"

    # 深度检测 claude.ai
    local raw code headers body
    raw=$(probe_full "https://claude.ai/" "${BROWSER_HEADERS[@]}")
    code=$(echo "$raw" | awk -F$'\x1e' '{print $1}')
    headers=$(echo "$raw" | awk -F$'\x1e' '{print $2}')
    body=$(echo "$raw" | awk -F$'\x1e' '{print $3}')

    local cf_ray cf_mitigated
    cf_ray=$(echo "$headers" | grep -i "^cf-ray:" | head -1 | sed 's/.*: *//; s/[\r\n]//g')
    cf_mitigated=$(echo "$headers" | grep -i "^cf-mitigated:" | head -1 | sed 's/.*: *//; s/[\r\n]//g')

    local is_challenge=0 is_turnstile=0 is_blocked=0 is_normal=0
    if echo "$body" | grep -qiE "cf_chl_opt|/cdn-cgi/challenge-platform|just a moment|checking your browser|enable javascript and cookies"; then
        is_challenge=1
    fi
    if echo "$body" | grep -qiE "turnstile|cf-turnstile"; then
        is_turnstile=1
    fi
    if echo "$body" | grep -qiE "sorry, you have been blocked|cloudflare ray id.*blocked|access denied|attention required"; then
        is_blocked=1
    fi
    if echo "$body" | grep -qiE "claude|anthropic|<title>Claude</title>"; then
        is_normal=1
    fi

    case "$code" in
        200)
            if [ "$is_blocked" = "1" ]; then
                result FAIL "claude.ai 网站" "200 但页面是 CF Block 页 - IP 被完全封禁"
            elif [ "$is_challenge" = "1" ] || [ "$is_turnstile" = "1" ]; then
                local kind="JS Challenge"
                [ "$is_turnstile" = "1" ] && kind="Turnstile/CAPTCHA"
                result WARN "claude.ai 网站" "200 但触发 CF $kind - 需通过验证"
            elif [ "$is_normal" = "1" ]; then
                result OK "claude.ai 网站" "200 - 页面正常返回"
            else
                result WARN "claude.ai 网站" "200 - 内容指纹不明确"
            fi
            ;;
        403)
            if [ "$is_blocked" = "1" ]; then
                result FAIL "claude.ai 网站" "403 - CF Block (IP/ASN 在黑名单)"
            elif [ -n "$cf_mitigated" ]; then
                result FAIL "claude.ai 网站" "403 - cf-mitigated: $cf_mitigated"
            else
                result FAIL "claude.ai 网站" "403 - 被 Anthropic 或 CF 拒绝"
            fi
            ;;
        429) result WARN "claude.ai 网站" "429 - 被限流" ;;
        451) result FAIL "claude.ai 网站" "451 - 法律原因不可用（地区）" ;;
        503)
            if [ "$is_challenge" = "1" ]; then
                result WARN "claude.ai 网站" "503 - CF 挑战页"
            else
                result FAIL "claude.ai 网站" "503 - 服务不可用"
            fi
            ;;
        000) result FAIL "claude.ai 网站" "连接失败" ;;
        *)   result WARN "claude.ai 网站" "状态码 $code" ;;
    esac

    [ -n "$cf_ray" ] && result INFO "CF-Ray" "$cf_ray"
    [ -n "$cf_mitigated" ] && result INFO "CF-Mitigated" "$cf_mitigated"

    if [ "$is_challenge" = "1" ] || [ "$is_turnstile" = "1" ] || [ "$is_blocked" = "1" ] || [ "$code" = "403" ]; then
        echo ""
        echo "  ${C_YLW}▼ CF 风控诊断${C_RST}"
        echo "  ${C_GRY}- API 正常但 claude.ai 被挡 = Cloudflare 浏览器风控，非 Anthropic 封 IP${C_RST}"
        echo "  ${C_GRY}- 数据中心 ASN（AWS/GCP/DO/Vultr 等）触发率极高${C_RST}"
        echo "  ${C_GRY}- 建议: 用住宅代理前置 / 换信誉好的小机房 / 此 IP 仅跑 API${C_RST}"
    fi

    if [ "$VERBOSE" = "1" ]; then
        local dump="/tmp/claude_ai_response_$$.html"
        echo "$body" > "$dump"
        result INFO "原始响应" "$dump"
    fi
}

test_gemini() {
    section "Google Gemini"

    if ! tcp_check "generativelanguage.googleapis.com"; then
        result FAIL "generativelanguage.googleapis.com:443 TCP" "无法建立连接"; return
    fi
    result OK "generativelanguage.googleapis.com:443 TCP"

    local resp code body
    resp=$(probe "https://gemini.google.com/" "${BROWSER_HEADERS[@]}")
    code=$(http_code "$resp")
    case "$code" in
        200|302) result OK   "gemini.google.com" "可正常访问" ;;
        403)     result FAIL "gemini.google.com" "403 - 当前地区不支持" ;;
        000)     result FAIL "gemini.google.com" "连接失败" ;;
        *)       result WARN "gemini.google.com" "状态码 $code" ;;
    esac

    resp=$(probe "https://generativelanguage.googleapis.com/v1/models")
    code=$(http_code "$resp"); body=$(http_body "$resp")
    case "$code" in
        401) result OK "Gemini API 验证" "401 - IP 通过" ;;
        403)
            if echo "$body" | grep -qiE "API_KEY|API key not valid|API key required"; then
                result OK   "Gemini API 验证" "403 - IP 通过，仅缺 API Key"
            elif echo "$body" | grep -qiE "location|country|region|not available|User location"; then
                result FAIL "Gemini API 验证" "403 - 地区不支持"
            else
                result WARN "Gemini API 验证" "403 - 原因不明"
            fi
            ;;
        000) result FAIL "Gemini API 验证" "连接失败" ;;
        *)   result WARN "Gemini API 验证" "状态码 $code" ;;
    esac
}

echo ""
echo "${C_MGT}AI 服务 IP 可用性检测 v2${C_RST}"
echo "${C_GRY}时间: $(date '+%Y-%m-%d %H:%M:%S') | 主机: $(hostname)${C_RST}"
[ -n "$IP_VERSION" ] && echo "${C_GRY}协议: ${IP_VERSION#-}${C_RST}"

if ! command -v curl >/dev/null 2>&1; then
    echo "${C_RED}错误: 未找到 curl${C_RST}"
    exit 1
fi

get_egress_info
test_openai
test_anthropic
test_gemini

section "检测完成"
echo "  ${C_GRY}OK=IP 通过 / FAIL=被拒 / WARN=需人工查看${C_RST}"
echo "  ${C_GRY}claude.ai 被 CF 拦但 API 正常时，此 IP 仍可用于跑 Claude API${C_RST}"
echo ""
