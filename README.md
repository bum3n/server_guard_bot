# 🛡 Server Guard v2.1 — Ваш личный Telegram-Бот для мониторинга и отслеживания состояния VPS

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+" />
  <img src="https://img.shields.io/badge/OS-Ubuntu%20%7C%20Debian-E95420?style=for-the-badge&logo=ubuntu&logoColor=white" alt="Ubuntu / Debian" />
  <img src="https://img.shields.io/badge/Telegram-pyTelegramBotAPI-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white" alt="Telegram Bot" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License" />
</p>

**Server Guard** — это мощный, автономный Telegram-бот для владельцев Linux-серверов (VPS). Он превращает ваш Telegram в полноценный карманный пульт управления сервером: отслеживает нагрузку процессора, оперативной памяти и диска, присылает алерты о падении системных служб, отражает атаки через Fail2Ban, автоматически создает резервные копии и отправляет ежедневные утренние сводки.

---

## ⚡ Быстрая установка за 60 секунд

Установка производится одной командой прямо на вашем сервере через интерактивный мастер:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/bum3n/server_guard_bot/main/install.sh)
```

Мастер установки на базе `whiptail` автоматически:
1. Проверит и установит системные зависимости (`python3-venv`, `git`, `curl`).
2. Запросит токен Telegram-бота и ваш Chat ID.
3. Развернет виртуальное окружение и установит библиотеки.
4. Создаст и запустит системную службу `systemd` (`server_guard.service`).

---

## 🚀 Основные возможности

| Раздел | Описание возможностей |
| :--- | :--- |
| **📊 Метрики** | Наглядные графические инфографики (Pillow) и текстовая сводка: CPU, RAM, SWAP, Диск, Uptime, сетевой трафик (Rx/Tx). Кнопка мгновенной выгрузки SWAP. |
| **📈 Графики 24ч** | Построение исторического 24-часового графика нагрузки и сетевого трафика (Matplotlib) на основе локальной базы SQLite. |
| **🛠 Службы и Сайты** | Непрерывный мониторинг systemd-служб (`nginx`, `docker`, `ssh` и др.) и HTTP-проверок. Управление службами прямо из чата (Старт / Стоп / Рестарт). |
| **🔝 Топ процессов** | Мониторинг наиболее прожорливых процессов по CPU, RAM и SWAP с понятными описаниями системных демонов. |
| **🛡 Защита Fail2Ban** | Мониторинг брутфорс-атак на SSH, просмотр списка забаненных IP-адресов и разблокировка в один клик. |
| **🚀 Тест скорости** | Встроенный замер пропускной способности интернет-канала VPS (Download / Upload / Ping). |
| **📦 Бэкап сервера** | Автоматическая сборка tar.gz архива конфигураций (`/etc/nginx`, `/etc/ssh`, сам бот) с отправкой прямо в Telegram и ротацией. |
| **🔗 Ссылки на сервисы** | Быстрый переход к вашим сайтам и веб-панелям. Добавление и удаление ссылок прямо из Telegram в пару кликов. |
| **📋 Ошибки в логах** | Просмотр реальных системных ошибок за последние 24 часа из `journalctl`. |
| **⏰ Ежедневный отчет** | Автоматическая утренняя сводка состояния сервера в 09:00 (МСК) с проверкой всех систем. |

---

## 📁 Структура проекта

```text
server_guard/
├── main.py              # Ядро Telegram-бота, диспетчер меню, диалоги и фоновый мониторинг
├── config.py            # Конфигурация: чтение .env, пороги алертов, списки служб
├── analyzer.py          # Анализ системы: Fail2Ban, SSL, Speedtest, SWAP, ошибки логов
├── card_generator.py    # Рендеринг графических статус-карточек и графиков (Pillow, Matplotlib)
├── backup_manager.py    # Создание, упаковка и отправка архивов резервных копий
├── metrics_store.py     # Локальная база SQLite для сбора временных рядов метрик
├── security_tools.py    # Аудит безопасности: отслеживание SSH-входов, GeoIP
├── maintenance.py       # Системное обслуживание: очистка диска, аптайм, пакеты apt
├── install.sh           # Интерактивный TUI-установщик для Ubuntu/Debian
├── requirements.txt     # Зависимости Python
├── .env.example         # Пример конфигурации переменных окружения
└── settings.example.json# Шаблон пользовательских настроек тумблеров
```

---

## 🛠 Ручная установка

Если вы предпочитаете настроить бота вручную без мастера `install.sh`:

1. **Клонируйте репозиторий:**
   ```bash
   git clone https://github.com/bum3n/server_guard_bot.git /opt/server_guard
   cd /opt/server_guard
   ```

2. **Создайте виртуальное окружение и установите зависимости:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Создайте файл конфигурации `.env`:**
   ```bash
   cp .env.example .env
   nano .env
   ```
   Заполните токен бота и ваш Telegram ID:
   ```ini
   BOT_TOKEN=1234567890:ABCdefGHIjklMNOpqrsTUVwxyz
   ADMIN_CHAT_ID=123456789
   SERVER_IP=1.2.3.4
   DOMAIN=localhost
   ```

4. **Настройте службу systemd:**
   Создайте файл `/etc/systemd/system/server_guard.service`:
   ```ini
   [Unit]
   Description=Server Guard Watchdog and Alerting Bot
   After=network.target network-online.target

   [Service]
   Type=simple
   User=root
   WorkingDirectory=/opt/server_guard
   ExecStart=/opt/server_guard/venv/bin/python /opt/server_guard/main.py
   Restart=always
   RestartSec=5
   Environment=PYTHONUNBUFFERED=1

   [Install]
   WantedBy=multi-user.target
   ```

5. **Запустите службу:**
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now server_guard
   ```

---

## 🔒 Безопасность и конфиденциальность

- **Никаких секретов в открытом виде**: все токены, ключи и ID хранятся исключительно в локальном файле `.env` (права доступа `600`).
- **Защита от несанкционированного доступа**: бот реагирует исключительно на команды из списка администраторов (`ADMIN_IDS`). Сообщения от посторонних пользователей полностью игнорируются.
- **Защищенные системные процессы**: критически важные службы (`systemd`, `sshd`, `nginx`, `init`) защищены от случайного завершения из интерфейса бота.

---

## 📄 Лицензия

Проект распространяется под открытой лицензией [MIT](LICENSE). Вы можете свободно использовать, модифицировать и распространять данный код.
