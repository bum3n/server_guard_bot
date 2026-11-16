#!/usr/bin/env bash
set -e

# ==============================================================================
# Server Guard — Интерактивный установщик для Ubuntu / Debian
# Репозиторий: https://github.com/bum3n/server_guard_bot
# ==============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Проверка прав суперпользователя (root)
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Ошибка: Этот скрипт необходимо запускать от имени root (или через sudo).${NC}"
    exit 1
fi

INSTALL_DIR="/opt/server_guard"
REPO_URL="https://github.com/bum3n/server_guard_bot.git"

echo -e "${CYAN}==> Подготовка окружения и проверка базовых утилит...${NC}"
apt-get update -qq
apt-get install -y -qq whiptail curl git python3 python3-venv python3-pip >/dev/null 2>&1

# 1. Приветствие
whiptail --title "🛡 Установка Server Guard" --msgbox \
"Добро пожаловать в установщик Server Guard!

Server Guard — это автономный Telegram-бот для непрерывного мониторинга состояния вашего Linux VPS, аудита безопасности, защиты от атак (Fail2Ban), контроля системных служб и автоматического резервного копирования.

Нажмите [OK], чтобы начать быструю настройку." 14 68

# 2. Ввод токена бота Telegram
BOT_TOKEN=""
while [ -z "$BOT_TOKEN" ]; do
    BOT_TOKEN=$(whiptail --title "🔑 Токен Telegram-бота" --inputbox \
"Введите токен вашего Telegram-бота (получите его у официального @BotFather):\n\nПример: 1234567890:ABCdefGHIjklMNOpqrsTUVwxyz" 12 68 3>&1 1>&2 2>&3)
    
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}[*] Установка отменена пользователем.${NC}"
        exit 0
    fi
    
    BOT_TOKEN=$(echo "$BOT_TOKEN" | tr -d '[:space:]')
    if [[ ! "$BOT_TOKEN" =~ ^[0-9]{8,12}:[a-zA-Z0-9_-]{30,50}$ ]]; then
        whiptail --title "⚠️ Ошибка формата" --msgbox "Введен некорректный токен бота. Убедитесь, что токен скопирован без пробелов и имеет вид 1234567890:ABC..." 10 68
        BOT_TOKEN=""
    fi
done

# 3. Ввод ID администратора
ADMIN_ID=""
while [ -z "$ADMIN_ID" ]; do
    ADMIN_ID=$(whiptail --title "👤 ID администратора Telegram" --inputbox \
"Введите ваш числовой Telegram Chat ID.\n(Узнать свой ID можно у ботов @userinfobot или @myidbot):\n\nПример: 123456789" 12 68 3>&1 1>&2 2>&3)
    
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}[*] Установка отменена пользователем.${NC}"
        exit 0
    fi
    
    ADMIN_ID=$(echo "$ADMIN_ID" | tr -d '[:space:]')
    if [[ ! "$ADMIN_ID" =~ ^[0-9]{5,15}$ ]]; then
        whiptail --title "⚠️ Ошибка формата" --msgbox "Telegram ID должен состоять только из цифр (от 5 до 12 символов)." 10 68
        ADMIN_ID=""
    fi
done

# 4. Определение внешнего IP и домена
DETECTED_IP=$(curl -s -m 5 https://api.ipify.org || hostname -I | awk '{print $1}')
SERVER_IP=$(whiptail --title "🌐 Сетевой IP-адрес сервера" --inputbox \
"Подтвердите или укажите внешний IP-адрес этого сервера:" 10 68 "$DETECTED_IP" 3>&1 1>&2 2>&3)

DOMAIN_INPUT=$(whiptail --title "🔗 Рабочий домен (опционально)" --inputbox \
"Если к серверу привязан домен, укажите его (например, example.com).\nЕсли домена нет, оставьте 'localhost':" 11 68 "localhost" 3>&1 1>&2 2>&3)
DOMAIN_INPUT=${DOMAIN_INPUT:-localhost}

# 5. Процесс развертывания
{
    echo 10
    echo "# Клонирование репозитория Server Guard..."
    if [ -d "$INSTALL_DIR" ]; then
        cd "$INSTALL_DIR" && git pull -q origin main || true
    else
        git clone -q "$REPO_URL" "$INSTALL_DIR"
    fi

    echo 35
    echo "# Создание виртуального окружения Python..."
    cd "$INSTALL_DIR"
    if [ ! -d "$INSTALL_DIR/venv" ]; then
        python3 -m venv "$INSTALL_DIR/venv"
    fi

    echo 60
    echo "# Установка зависимостей Python (psutil, telebot, Pillow, matplotlib)..."
    "$INSTALL_DIR/venv/bin/pip" install --upgrade pip -q >/dev/null 2>&1
    "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q >/dev/null 2>&1

    echo 75
    echo "# Генерация защищенной конфигурации .env..."
    cat > "$INSTALL_DIR/.env" <<EOF
# Server Guard Environment Configuration
BOT_TOKEN=$BOT_TOKEN
ADMIN_CHAT_ID=$ADMIN_ID
ADMIN_CHAT_IDS=$ADMIN_ID
SERVER_IP=$SERVER_IP
DOMAIN=$DOMAIN_INPUT
EOF
    chmod 600 "$INSTALL_DIR/.env"

    echo 85
    echo "# Создание системной службы systemd..."
    cat > /etc/systemd/system/server_guard.service <<EOF
[Unit]
Description=Server Guard Watchdog and Alerting Bot
After=network.target network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/main.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    echo 95
    echo "# Запуск и включение службы server_guard.service..."
    systemctl daemon-reload
    systemctl enable --now server_guard.service >/dev/null 2>&1
    sleep 2

    echo 100
    echo "# Завершено!"
} | whiptail --title "⏳ Установка и настройка Server Guard" --gauge "Начало процесса установки..." 8 70 0

# Проверка статуса запуска
if systemctl is-active --quiet server_guard.service; then
    whiptail --title "🎉 Установка успешно завершена!" --msgbox \
"Бот Server Guard успешно установлен и запущен!

Служба: server_guard.service (активна)
Директория: $INSTALL_DIR

Что делать дальше:
1. Откройте вашего Telegram-бота.
2. Отправьте команду /start.
3. Перед вами откроется панель мониторинга и главное меню!

Полезные команды сервера:
• Статус службы: systemctl status server_guard
• Просмотр логов: journalctl -u server_guard -f
• Перезапуск: systemctl restart server_guard" 17 70
else
    whiptail --title "⚠️ Ошибка запуска службы" --msgbox \
"Установка завершилась, но служба не смогла запуститься в автоматическом режиме.

Проверьте логи командой:
journalctl -u server_guard -n 30 --no-pager" 12 70
fi
