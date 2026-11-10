#!/usr/bin/env bash
# xui-reality-harden
# Автонастройка VPS с 3x-ui под рекомендации статьи https://habr.com/ru/articles/1103460/
#   - пользовательский трафик НЕ выходит с IP входа (WARP или sendThrough со 2-го IP)
#   - панель только на 127.0.0.1, файрвол, отключение IPv6
#   - генерация параметров для inbound VLESS + XHTTP + Reality (self-steal)
#
# Использование:
#   sudo ./harden.sh                      # интерактивно
#   sudo ./harden.sh --mode warp --domain de.example.com
#   sudo ./harden.sh --mode sendthrough --exit-ip 203.0.113.20 --domain de.example.com
#   sudo ./harden.sh verify
#   sudo ./harden.sh rollback
set -euo pipefail

DB="/etc/x-ui/x-ui.db"
BACKUP_DIR="/root/xui-harden-backups"
WORK_DIR="/etc/xui-harden"
PARAMS_FILE="/root/reality-params.txt"

REALITY_PORT=12443
HY_PORT=5443
AWG_PORT=3373
SUB_PORT=2096

CMD="apply"
MODE=""
EXIT_IP=""
DOMAIN=""
SSH_PORT=""
DO_UFW=1
DO_IPV6=1
DO_PANEL_LOCK=1
OPEN_SUB=1

log()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
cat <<'EOF'
Команды:
  apply (по умолчанию)   применить настройки
  verify                 проверить текущее состояние
  rollback               вернуть последнюю резервную копию базы 3x-ui

Опции apply:
  --mode warp|sendthrough   способ выхода (WARP или со второго IP)
  --exit-ip IP              второй IP для sendThrough (выход)
  --domain DOMAIN           ваш домен для self-steal (должен указывать на ВХОДНОЙ IP)
  --ssh-port N              порт SSH (по умолчанию определяется автоматически)
  --reality-port N          порт Reality (по умолчанию 12443)
  --hy-port N               порт Hysteria UDP (по умолчанию 5443)
  --awg-port N              порт AmneziaWG UDP (по умолчанию 3373)
  --sub-port N              порт подписок (по умолчанию 2096)
  --close-sub               не открывать порт подписок в файрволе
  --no-ufw                  не трогать файрвол
  --no-ipv6-off             не отключать IPv6
  --no-panel-lock           не переводить панель на 127.0.0.1
EOF
}

# ---------- разбор аргументов ----------
if [[ $# -gt 0 ]]; then
  case "$1" in
    apply|verify|rollback) CMD="$1"; shift ;;
  esac
fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2 ;;
    --exit-ip) EXIT_IP="${2:-}"; shift 2 ;;
    --domain) DOMAIN="${2:-}"; shift 2 ;;
    --ssh-port) SSH_PORT="${2:-}"; shift 2 ;;
    --reality-port) REALITY_PORT="${2:-}"; shift 2 ;;
    --hy-port) HY_PORT="${2:-}"; shift 2 ;;
    --awg-port) AWG_PORT="${2:-}"; shift 2 ;;
    --sub-port) SUB_PORT="${2:-}"; shift 2 ;;
    --close-sub) OPEN_SUB=0; shift ;;
    --no-ufw) DO_UFW=0; shift ;;
    --no-ipv6-off) DO_IPV6=0; shift ;;
    --no-panel-lock) DO_PANEL_LOCK=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Неизвестный параметр: $1 (см. --help)" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "Запустите от root: sudo $0"

# ---------- общие функции ----------
default_src_ip() { ip -4 route get 1.1.1.1 2>/dev/null | grep -oE 'src [0-9.]+' | awk '{print $2}' | head -1; }

detect_ssh_port() {
  local p=""
  if command -v sshd >/dev/null 2>&1; then
    p="$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}')" || true
  fi
  echo "${p:-22}"
}

resolve_domain_ip() { getent ahostsv4 "$1" 2>/dev/null | awk '{print $1; exit}'; }

stop_xui()  { systemctl stop x-ui  2>/dev/null || true; }
start_xui() { systemctl start x-ui 2>/dev/null || systemctl restart x-ui; }

# ---------- rollback ----------
if [[ "$CMD" == "rollback" ]]; then
  last="$(ls -1t "$BACKUP_DIR"/x-ui.db.* 2>/dev/null | head -1 || true)"
  [[ -n "$last" ]] || die "Резервных копий в $BACKUP_DIR нет"
  log "Восстанавливаю $last"
  stop_xui
  cp -f "$last" "$DB"
  start_xui
  log "Готово. Правила файрвола и sysctl откатывайте вручную (ufw status, /etc/sysctl.d/99-noipv6.conf)."
  exit 0
fi

# ---------- verify ----------
if [[ "$CMD" == "verify" ]]; then
  [[ -f "$DB" ]] || die "Не найдена база 3x-ui: $DB"
  log "Служба x-ui: $(systemctl is-active x-ui || true)"

  log "Исходящие/ключевые настройки в шаблоне Xray:"
  DB="$DB" python3 - <<'PY'
import json, os, sqlite3
con = sqlite3.connect(os.environ["DB"])
get = lambda k: (con.execute("SELECT value FROM settings WHERE key=?", (k,)).fetchone() or [None])[0]
tpl = json.loads(get("xrayTemplateConfig") or "{}")
outs = tpl.get("outbounds", [])
print("   outbounds:", [(o.get("tag"), o.get("protocol"), o.get("sendThrough", "")) for o in outs])
bad = [o.get("tag") for o in outs if o.get("protocol") == "freedom" and not o.get("sendThrough")]
print("   ОПАСНО: freedom без sendThrough:" if bad else "   freedom без sendThrough: нет (хорошо)", bad or "")
rules = (tpl.get("routing") or {}).get("rules", [])
print("   последнее правило ->", rules[-1].get("outboundTag") if rules else "нет правил")
print("   domainStrategy:", (tpl.get("routing") or {}).get("domainStrategy"))
print("   webListen:", get("webListen") or "(пусто = все интерфейсы!)", " webPort:", get("webPort"))
PY

  log "Слушающие порты:"
  ss -tulpn 2>/dev/null | awk 'NR==1 || /:(22|80|443|2096|5987|5443|3373|12443)\s/' || true

  v6="$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo '?')"
  log "IPv6 отключён (1=да): $v6"

  if command -v ufw >/dev/null 2>&1; then
    log "UFW:"; ufw status | sed 's/^/   /'
  fi

  if [[ -n "$EXIT_IP" ]]; then
    got="$(curl -4 -s --max-time 10 --interface "$EXIT_IP" https://api.ipify.org || true)"
    log "Внешний IP при выходе через $EXIT_IP: ${got:-не удалось определить}"
  fi

  if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -qi amnezia; then
    warn "Найден контейнер AmneziaWG: его клиенты выходят с IP сервера (NAT на хосте) и обходят защиту. См. README."
  fi
  echo
  log "Финальная проверка: подключитесь клиентом и откройте ipify.org. Должен быть IP WARP/второго адреса, а НЕ входной."
  exit 0
fi

# ---------- apply ----------
command -v apt-get >/dev/null 2>&1 || die "Скрипт рассчитан на Debian/Ubuntu (apt)."
[[ -f "$DB" ]] || die "Не найдена база 3x-ui ($DB). Сначала установите 3x-ui."
systemctl list-unit-files 2>/dev/null | grep -q '^x-ui' || die "Служба x-ui не найдена."

if [[ -z "$MODE" ]]; then
  [[ -t 0 ]] || die "Укажите --mode warp|sendthrough"
  echo "Выберите способ выхода пользовательского трафика:"
  echo "  1) warp         - через Cloudflare WARP (нужен только один IP)"
  echo "  2) sendthrough  - с ВТОРОГО IP этого сервера"
  read -rp "Номер [1/2]: " a
  case "$a" in 1) MODE=warp ;; 2) MODE=sendthrough ;; *) die "Нужно 1 или 2" ;; esac
fi
[[ "$MODE" == "warp" || "$MODE" == "sendthrough" ]] || die "--mode: warp или sendthrough"

if [[ -z "$DOMAIN" && -t 0 ]]; then
  read -rp "Ваш домен для self-steal (например de.example.com, Enter - пропустить): " DOMAIN
fi

log "Устанавливаю зависимости"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl ufw python3 openssl ca-certificates iproute2 >/dev/null

ENTRY_IP=""
if [[ -n "$DOMAIN" ]]; then
  ENTRY_IP="$(resolve_domain_ip "$DOMAIN" || true)"
  [[ -n "$ENTRY_IP" ]] || warn "Домен $DOMAIN не резолвится. Проверьте A-запись."
fi
[[ -n "$ENTRY_IP" ]] || ENTRY_IP="$(default_src_ip)"
log "Входной IP (куда подключаются клиенты): ${ENTRY_IP:-не определён}"

if [[ "$MODE" == "sendthrough" ]]; then
  if [[ -z "$EXIT_IP" ]]; then
    echo "Адреса на интерфейсах сервера:"
    ip -4 -o addr show scope global | awk '{print "  " $2 "  " $4}'
    [[ -t 0 ]] || die "Укажите --exit-ip"
    read -rp "Какой IP использовать как ВЫХОД (не входной!): " EXIT_IP
  fi
  EXIT_IP="${EXIT_IP%%/*}"
  [[ "$EXIT_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Некорректный IP: $EXIT_IP"
  ip -4 -o addr show | grep -qw "$EXIT_IP" || die "IP $EXIT_IP не назначен ни одному интерфейсу. Сначала настройте его в системе."
  [[ "$EXIT_IP" != "$ENTRY_IP" ]] || die "Выходной IP совпадает с входным ($ENTRY_IP). Смысл схемы в том, чтобы они различались."
  log "Проверяю, что трафик реально выходит с $EXIT_IP"
  got="$(curl -4 -s --max-time 12 --interface "$EXIT_IP" https://api.ipify.org || true)"
  if [[ "$got" != "$EXIT_IP" ]]; then
    die "С интерфейса $EXIT_IP внешний адрес: '${got:-нет ответа}'. Второй IP не маршрутизируется. Проверьте настройку у хостера (или используйте --mode warp)."
  fi
  log "OK: выход с $EXIT_IP работает"
  if [[ -n "$DOMAIN" ]]; then
    d_ip="$(resolve_domain_ip "$DOMAIN" || true)"
    [[ "$d_ip" != "$EXIT_IP" ]] || die "Домен $DOMAIN указывает на выходной IP. Он должен указывать на входной."
  fi
fi

# --- резервная копия ---
mkdir -p "$BACKUP_DIR"
bk="$BACKUP_DIR/x-ui.db.$(date +%Y%m%d-%H%M%S)"
cp -f "$DB" "$bk"
log "Резервная копия: $bk (откат: sudo $0 rollback)"

# --- WARP ---
WARP_PRIV=""; WARP_ADDR=""; WARP_PUB=""
if [[ "$MODE" == "warp" ]]; then
  mkdir -p "$WORK_DIR"; chmod 700 "$WORK_DIR"
  cd "$WORK_DIR"
  case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) die "Неподдерживаемая архитектура $(uname -m)" ;;
  esac
  if [[ ! -x ./wgcf ]]; then
    log "Скачиваю wgcf"
    URL="$(curl -fsSL https://api.github.com/repos/ViRb3/wgcf/releases/latest | grep -oE "https://[^\"]*linux_${ARCH}" | head -1 || true)"
    [[ -n "$URL" ]] || die "Не удалось получить ссылку на wgcf (лимит GitHub API?). Повторите позже."
    curl -fsSL -o wgcf "$URL"; chmod +x wgcf
  fi
  if [[ ! -f wgcf-account.toml ]]; then
    log "Регистрирую аккаунт WARP"
    ./wgcf register --accept-tos >/dev/null || die "Регистрация WARP не удалась (бывает блокировка из локации сервера). Используйте --mode sendthrough или другой сервер."
  fi
  ./wgcf generate >/dev/null
  WARP_PRIV="$(grep -m1 '^PrivateKey' wgcf-profile.conf | cut -d= -f2- | tr -d ' \r')"
  WARP_PUB="$(grep -m1 '^PublicKey' wgcf-profile.conf | cut -d= -f2- | tr -d ' \r')"
  WARP_ADDR="$(grep -m1 '^Address' wgcf-profile.conf | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | head -1)"
  [[ -n "$WARP_PRIV" && -n "$WARP_PUB" && -n "$WARP_ADDR" ]] || die "Не удалось разобрать wgcf-profile.conf"
  log "WARP-профиль готов"
fi

# --- шаблон Xray + панель ---
log "Правлю шаблон Xray в базе 3x-ui"
stop_xui
set +e
DB="$DB" MODE="$MODE" EXIT_IP="$EXIT_IP" WARP_PRIV="$WARP_PRIV" WARP_ADDR="$WARP_ADDR" WARP_PUB="$WARP_PUB" \
LOCK_PANEL="$DO_PANEL_LOCK" python3 - <<'PY'
import json, os, sqlite3, sys

con = sqlite3.connect(os.environ["DB"])
cur = con.cursor()
row = cur.execute("SELECT value FROM settings WHERE key='xrayTemplateConfig'").fetchone()
if not row or not (row[0] or "").strip():
    sys.exit("NO_TEMPLATE")
tpl = json.loads(row[0])

mode = os.environ["MODE"]
if mode == "warp":
    tag = "warp"
    egress = {
        "tag": tag, "protocol": "wireguard",
        "settings": {
            "secretKey": os.environ["WARP_PRIV"],
            "address": [os.environ["WARP_ADDR"]],
            "peers": [{
                "publicKey": os.environ["WARP_PUB"],
                "allowedIPs": ["0.0.0.0/0"],
                "endpoint": "162.159.192.1:2408",
            }],
            "mtu": 1280,
            "domainStrategy": "ForceIPv4",
        },
    }
else:
    tag = "exit-ip2"
    egress = {
        "tag": tag, "protocol": "freedom",
        "sendThrough": os.environ["EXIT_IP"],
        "settings": {"domainStrategy": "UseIPv4"},
    }

old_rules = (tpl.get("routing") or {}).get("rules") or []
keep = [r for r in old_rules if r.get("outboundTag") == "api"]
rules = keep + [
    {"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"},
    {"type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked"},
    {"type": "field", "network": "tcp,udp", "outboundTag": tag},
]
# egress первым = outbound по умолчанию; freedom без sendThrough намеренно нет
tpl["outbounds"] = [egress, {"tag": "blocked", "protocol": "blackhole", "settings": {}}]
tpl["routing"] = {"domainStrategy": "IPOnDemand", "rules": rules}

def put(k, v):
    n = cur.execute("UPDATE settings SET value=? WHERE key=?", (v, k)).rowcount
    if n == 0:
        cur.execute("INSERT INTO settings(key, value) VALUES(?, ?)", (k, v))

put("xrayTemplateConfig", json.dumps(tpl, indent=2, ensure_ascii=False))
if os.environ.get("LOCK_PANEL") == "1":
    put("webListen", "127.0.0.1")
con.commit()
print("TEMPLATE_OK")
PY
rc=$?
set -e
if [[ $rc -ne 0 ]]; then
  start_xui
  die "Не удалось изменить шаблон. Если вывод 'NO_TEMPLATE': откройте панель -> Настройки Xray -> Сохранить один раз, затем запустите скрипт снова. База не изменена."
fi
start_xui
log "Шаблон обновлён, x-ui перезапущен"
[[ "$DO_PANEL_LOCK" -eq 1 ]] && log "Панель теперь слушает только 127.0.0.1 (доступ через SSH-туннель)"

# --- IPv6 ---
if [[ "$DO_IPV6" -eq 1 ]]; then
  cat >/etc/sysctl.d/99-noipv6.conf <<'EOF'
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
EOF
  sysctl --system >/dev/null
  log "IPv6 отключён"
fi

# --- файрвол ---
if [[ "$DO_UFW" -eq 1 ]]; then
  [[ -n "$SSH_PORT" ]] || SSH_PORT="$(detect_ssh_port)"
  log "Настраиваю UFW (SSH порт: $SSH_PORT)"
  ufw --force reset >/dev/null
  ufw default deny incoming >/dev/null
  ufw default allow outgoing >/dev/null
  if [[ "$MODE" == "sendthrough" ]]; then
    # выходной IP должен быть "тёмным": на нём ничего не отвечает снаружи
    ufw deny in to "$EXIT_IP" >/dev/null
  fi
  ufw allow "${SSH_PORT}/tcp" >/dev/null
  ufw allow 80/tcp  >/dev/null
  ufw allow 443/tcp >/dev/null
  ufw allow "${REALITY_PORT}/tcp" >/dev/null
  ufw allow "${HY_PORT}/udp" >/dev/null
  ufw allow "${AWG_PORT}/udp" >/dev/null
  [[ "$OPEN_SUB" -eq 1 ]] && ufw allow "${SUB_PORT}/tcp" >/dev/null
  ufw --force enable >/dev/null
  log "UFW включён. Порт панели наружу не открыт."
fi

# --- параметры Reality ---
XRAY_BIN="$(ls -1 /usr/local/x-ui/bin/xray-linux-* 2>/dev/null | head -1 || true)"
{
  echo "# Параметры для inbound VLESS + XHTTP + Reality (создайте inbound в панели по ним)"
  echo "port:        $REALITY_PORT"
  echo "protocol:    vless (flow у клиентов ПУСТОЙ)"
  echo "transport:   XHTTP, mode=auto"
  echo "host:        ${DOMAIN:-ВАШ_ДОМЕН}"
  echo "path:        /$(openssl rand -hex 6)"
  echo "xPaddingBytes: 100-1000"
  echo "security:    reality"
  echo "target(dest): 127.0.0.1:443"
  echo "serverNames: ${DOMAIN:-ВАШ_ДОМЕН}"
  echo "fingerprint: chrome"
  echo "shortIds:    $(openssl rand -hex 2), $(openssl rand -hex 8), $(openssl rand -hex 4)"
  echo "sniffing:    enabled, http+tls+quic, routeOnly=on"
  echo
  if [[ -n "$XRAY_BIN" ]]; then
    echo "# x25519 (privateKey -> в inbound, publicKey -> клиентам):"
    "$XRAY_BIN" x25519 2>&1 || true
  else
    echo "# xray не найден; в панели нажмите 'Get New Cert' в настройках Reality"
  fi
} > "$PARAMS_FILE"
chmod 600 "$PARAMS_FILE"
log "Параметры Reality сохранены: $PARAMS_FILE"

# --- проверка сайта-донора ---
if [[ -n "$DOMAIN" ]]; then
  out="$(echo | openssl s_client -connect 127.0.0.1:443 -servername "$DOMAIN" -tls1_3 -alpn h2 2>/dev/null || true)"
  if echo "$out" | grep -q 'TLSv1.3' && echo "$out" | grep -q 'ALPN protocol: h2'; then
    log "Сайт $DOMAIN на 127.0.0.1:443 отдаёт TLS 1.3 + h2 (подходит для self-steal)"
  else
    warn "Сайт $DOMAIN на 127.0.0.1:443 не отдаёт TLS 1.3 + h2. Включите 'http2' и TLSv1.3 в nginx, иначе Reality будет заметен."
  fi
fi

if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -qi amnezia; then
  warn "AmneziaWG (docker) выпускает клиентов с IP сервера и обходит эту защиту. Либо отключите его, либо заведите его трафик в WARP/второй IP (см. README)."
fi

echo
log "Готово. Дальше: создайте inbound по $PARAMS_FILE и проверьте: sudo $0 verify ${EXIT_IP:+--exit-ip $EXIT_IP}"
