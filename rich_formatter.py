"""
Telegram Rich Markdown Formatter & Safe Sender for Server Guard.
Natively utilizes Telegram Bot API 10.1+ (sendRichMessage & editMessageText)
with full-width layout, multi-level headers (#, ##, ###), native tables,
expandable spoilers (<details><summary>), checklists, and quotes.
"""
import re
import html
import logging
from typing import List
from telebot import types

log = logging.getLogger("server_guard")


def to_rich_markdown(text: str) -> str:
    """
    Преобразует HTML или смешанный текст в чистый Telegram Rich Markdown.
    Если текст уже в Markdown, сохраняет его структуру без искажений.
    """
    if not text:
        return ""

    # 1. Защита уже существующих блоков кода ```lang\ncode```
    code_blocks = []
    def save_cb(m):
        code = m.group(2)
        idx = len(code_blocks)
        code_blocks.append(f"```{m.group(1)}\n{code.strip()}\n```")
        return f"%%CB_{idx}%%"
    text = re.sub(r'```([a-zA-Z0-9_-]*)\r?\n?([\s\S]*?)```', save_cb, text)

    # 2. Сворачиваемые блоки: <blockquote expandable> или <details><summary>
    def rep_expandable(m):
        content = m.group(1).strip()
        title_m = re.match(r'^(?:<b>|\*\*)(.*?)(?:</b>|\*\*)\s*\n?([\s\S]*)$', content)
        if title_m:
            title = title_m.group(1).strip()
            body = title_m.group(2).strip()
            return f"\n<details><summary>{title}</summary>\n{body}\n</details>\n"
        return f"\n<details><summary>Подробнее</summary>\n{content}\n</details>\n"
    text = re.sub(r'<blockquote\s+expandable>([\s\S]*?)</blockquote>', rep_expandable, text, flags=re.IGNORECASE)

    # 3. Цитаты: <blockquote>text</blockquote> -> > text
    def rep_quote(m):
        content = m.group(1).strip()
        lines = [f"> {line}" for line in content.splitlines()]
        return "\n" + "\n".join(lines) + "\n"
    text = re.sub(r'<blockquote>([\s\S]*?)</blockquote>', rep_quote, text, flags=re.IGNORECASE)

    # 3b. Сохранение переводов строк внутри цитат (> line 1\n> line 2 -> двойной пробел на конце)
    def fix_quote_linebreaks(m):
        quote_block = m.group(0)
        lines = quote_block.splitlines()
        new_lines = []
        for i, l in enumerate(lines):
            if i < len(lines) - 1 and not l.endswith("  "):
                new_lines.append(l + "  ")
            else:
                new_lines.append(l)
        return "\n".join(new_lines)
    text = re.sub(r'(?m)^>(?:[^\n]*\n?)+', fix_quote_linebreaks, text)

    # 4. Преформатированные блоки: <pre><code>...</code></pre> или <pre>...</pre>
    text = re.sub(r'<pre><code>([\s\S]*?)</code></pre>', r'```\n\1\n```', text, flags=re.IGNORECASE)
    text = re.sub(r'<pre>([\s\S]*?)</pre>', r'```\n\1\n```', text, flags=re.IGNORECASE)

    # 5. Инлайн-код: <code>code</code> -> `code`
    text = re.sub(r'<code>(.*?)</code>', r'`\1`', text, flags=re.IGNORECASE)

    # 6. Жирный шрифт: <b>text</b> или <strong>text</strong> -> **text**
    text = re.sub(r'<(?:b|strong)>(.*?)</(?:b|strong)>', r'**\1**', text, flags=re.IGNORECASE)

    # 7. Курсив: <i>text</i> или <em>text</em> -> _text_
    text = re.sub(r'<(?:i|em)>(.*?)</(?:i|em)>', r'_\1_', text, flags=re.IGNORECASE)

    # 8. Спойлеры: <tg-spoiler>text</tg-spoiler> -> ||text||
    text = re.sub(r'<tg-spoiler>(.*?)</tg-spoiler>', r'||\1||', text, flags=re.IGNORECASE)

    # 9. Ссылки: <a href="url">text</a> -> [text](url)
    text = re.sub(r'<a\s+href=[\"\x27](.*?)[\"\x27]>(.*?)</a>', r'[\2](\1)', text, flags=re.IGNORECASE)

    # 10. Декодирование стандартных HTML сущностей
    text = text.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("&quot;", "\"")

    # 11. Восстановление сохраненных блоков кода
    for i, b in enumerate(code_blocks):
        text = text.replace(f"%%CB_{i}%%", b)

    return text.strip()


def to_telegram_html(text: str) -> str:
    """Обратная совместимость: возвращает HTML если требуется."""
    return to_rich_markdown(text)

md_to_telegram_html = to_rich_markdown
rich_to_telegram_html = to_rich_markdown


def split_markdown(text: str, max_chunk_size: int = 30000) -> List[str]:
    """Разбивает длинный Markdown текст на части без разрыва блоков."""
    if len(text) <= max_chunk_size:
        return [text]

    chunks = []
    lines = text.split("\n")
    current_chunk = []
    current_length = 0

    for line in lines:
        line_len = len(line) + 1
        if current_length + line_len > max_chunk_size and current_chunk:
            chunks.append("\n".join(current_chunk))
            current_chunk = [line]
            current_length = line_len
        else:
            current_chunk.append(line)
            current_length += line_len

    if current_chunk:
        chunks.append("\n".join(current_chunk))

    return chunks


def safe_send_message(bot, chat_id: int, text: str, reply_markup=None, disable_web_page_preview: bool = True):
    """
    Отправка сообщения в режиме Telegram Bot API 10.1+ Rich Markdown (sendRichMessage).
    Поддерживает нативные таблицы, заголовки (#, ##, ###), аккордеоны (<details><summary>),
    чек-листы и полный охват ширины экрана.
    """
    clean_md = to_rich_markdown(text)
    chunks = split_markdown(clean_md, max_chunk_size=30000)
    last_msg = None

    for idx, chunk in enumerate(chunks):
        markup = reply_markup if idx == len(chunks) - 1 else None
        try:
            rm = types.InputRichMessage(markdown=chunk)
            last_msg = bot.send_rich_message(chat_id, rich_message=rm, reply_markup=markup)
        except Exception as e:
            log.warning(f"safe_send_message send_rich_message failed: {e}. Trying HTML fallback...")
            try:
                # Попытка отправки в режиме HTML
                last_msg = bot.send_message(
                    chat_id,
                    chunk,
                    parse_mode="HTML",
                    reply_markup=markup,
                    disable_web_page_preview=disable_web_page_preview
                )
            except Exception as e2:
                log.warning(f"safe_send_message HTML fallback failed: {e2}. Falling back to plain text.")
                plain = re.sub(r'<[^>]+>', '', chunk)
                try:
                    last_msg = bot.send_message(
                        chat_id,
                        plain,
                        parse_mode=None,
                        reply_markup=markup,
                        disable_web_page_preview=disable_web_page_preview
                    )
                except Exception as e3:
                    log.error(f"safe_send_message fatal fallback error: {e3}")
    return last_msg


def safe_edit_message(bot, chat_id: int, message_id: int, text: str, reply_markup=None, disable_web_page_preview: bool = True):
    """
    Редактирование сообщения в режиме Telegram Bot API 10.1+ Rich Markdown (editMessageText).
    """
    clean_md = to_rich_markdown(text)
    try:
        rm = types.InputRichMessage(markdown=clean_md)
        return bot.edit_message_text(
            chat_id=chat_id,
            message_id=message_id,
            rich_message=rm,
            reply_markup=reply_markup
        )
    except Exception as e:
        err_str = str(e).lower()
        if "message is not modified" in err_str:
            return None
        log.warning(f"safe_edit_message rich failed: {e}. Trying HTML fallback...")
        try:
            return bot.edit_message_text(
                clean_md,
                chat_id=chat_id,
                message_id=message_id,
                parse_mode="HTML",
                reply_markup=reply_markup,
                disable_web_page_preview=disable_web_page_preview
            )
        except Exception as e2:
            if "message is not modified" in str(e2).lower():
                return None
            log.warning(f"safe_edit_message HTML fallback failed: {e2}. Plain fallback...")
            plain = re.sub(r'<[^>]+>', '', clean_md)
            try:
                return bot.edit_message_text(
                    plain,
                    chat_id=chat_id,
                    message_id=message_id,
                    parse_mode=None,
                    reply_markup=reply_markup,
                    disable_web_page_preview=disable_web_page_preview
                )
            except Exception as e3:
                if "message is not modified" in str(e3).lower():
                    return None
                log.error(f"safe_edit_message fatal error: {e3}")
                return None


def caption_to_html(text: str) -> str:
    """Конвертирует базовую Markdown-разметку в валидный HTML для caption в send_photo."""
    if not text:
        return ""
    # Преобразуем заголовки #, ##, ### в жирный текст <b>Заголовок</b>
    text = re.sub(r'^\s*#{1,6}\s*(.+)$', r'<b>\1</b>', text, flags=re.MULTILINE)
    # **жирный** в <b>жирный</b>
    text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
    # `код` в <code>код</code>
    text = re.sub(r'`([^`\n]+)`', r'<code>\1</code>', text)
    # _курсив_ в <i>курсив</i>
    text = re.sub(r'(?<!\w)_([^_]+?)_(?!\w)', r'<i>\1</i>', text)
    return text.strip()


def safe_send_photo(bot, chat_id: int, photo, caption: str = "", reply_markup=None):
    """
    Безопасная отправка инфографики с отчетом.
    Если отчет содержит элементы Rich Markdown (заголовки #, таблицы |, аккордеоны)
    или длиннее 500 символов, отправляет фото с чистой HTML-подписью, а полный отчет
    в формате Telegram Rich Markdown отправляет следом на всю ширину экрана.
    """
    clean_md = to_rich_markdown(caption) if caption else ""
    has_rich = any(marker in clean_md for marker in ("# ", "## ", "| :---", "<details>", "\n|")) or len(clean_md) > 500

    if has_rich:
        try:
            if hasattr(photo, "seek"):
                photo.seek(0)
            bot.send_photo(
                chat_id,
                photo,
                caption="📊 <b>Инфографика ресурсов и стабильности VPS</b>",
                parse_mode="HTML"
            )
        except Exception as e:
            log.warning(f"safe_send_photo header error: {e}")
        return safe_send_message(bot, chat_id, clean_md, reply_markup=reply_markup)

    html_caption = caption_to_html(clean_md)
    try:
        if hasattr(photo, "seek"):
            photo.seek(0)
        return bot.send_photo(
            chat_id,
            photo,
            caption=html_caption if html_caption else None,
            parse_mode="HTML" if html_caption else None,
            reply_markup=reply_markup
        )
    except Exception as e:
        log.warning(f"safe_send_photo failed: {e}. Trying plain text fallback...")
        try:
            if hasattr(photo, "seek"):
                photo.seek(0)
            plain_cap = re.sub(r'<[^>]+>', '', html_caption) if html_caption else None
            return bot.send_photo(
                chat_id,
                photo,
                caption=plain_cap,
                parse_mode=None,
                reply_markup=reply_markup
            )
        except Exception as e2:
            log.error(f"safe_send_photo fatal error: {e2}")
            return None
