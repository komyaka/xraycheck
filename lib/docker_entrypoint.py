#!/usr/bin/env python3
"""
Entrypoint для Docker: ограничивает исходящий доступ контейнера только
CIDR из whitelist (CIDR_WHITELIST_URL). IP прокси в разрешённые не добавляются.
"""
import ipaddress
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

CIDR_WHITELIST_URL = os.environ.get(
    "CIDR_WHITELIST_URL",
    "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/cidrwhitelist.txt",
)
LINKS_FILE = os.environ.get("LINKS_FILE", "links.txt")


def fetch(url: str) -> str:
    # Валидация URL перед использованием
    try:
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Некорректный URL: {url}")
        # Проверка на управляющие символы
        if any(ord(c) < 32 and c not in '\t\n\r' for c in url):
            raise ValueError(f"URL содержит управляющие символы: {url}")
    except Exception as e:
        raise ValueError(f"Ошибка валидации URL: {e}")
    
    with urllib.request.urlopen(url, timeout=30) as r:
        return r.read().decode("utf-8", errors="replace")


def parse_vless_lines(text: str) -> list[tuple[str, str]]:
    """Строки с прокси-протоколами: (ссылка, полная_строка). Поддерживает VLESS, VMess, Trojan, Shadowsocks."""
    supported_protocols = ("vless://", "vmess://", "trojan://", "ss://")
    result = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Проверяем, начинается ли строка с одного из поддерживаемых протоколов
        for protocol in supported_protocols:
            if line.startswith(protocol):
                link = line.split(maxsplit=1)[0].strip()
                if link:
                    result.append((link, line))
                break
    return result


def merge_keys_from_urls(urls: list[str]) -> str:
    """Загружает списки по каждому URL, объединяет ключи (дедупликация по ссылке), возвращает текст."""
    seen: set[str] = set()
    lines: list[str] = []
    total = len(urls)
    print(f"Парсинг и объединение ключей из {total} ссылок:")
    for idx, url in enumerate(urls, 1):
        try:
            text = fetch(url)
            parsed = parse_vless_lines(text)
            new_count = 0
            for link, full in parsed:
                if link not in seen:
                    seen.add(link)
                    lines.append(full)
                    new_count += 1
            print(f"  [{idx}/{total}] {url} -> получено {len(parsed)} ключей, новых {new_count}, всего уникальных: {len(lines)}")
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError) as e:
            # При ошибке загрузки или валидации URL помечаем URL и продолжаем
            error_msg = str(e)
            # Обрезаем длинные сообщения об ошибках
            if len(error_msg) > 100:
                error_msg = error_msg[:97] + "..."
            print(f"  [{idx}/{total}] Ошибка загрузки: {url} -> {error_msg} (пропущено)", file=sys.stderr)
            continue
    print(f"Итого уникальных ключей: {len(lines)}\n")
    return "\n".join(lines)


def parse_cidr_whitelist(text: str) -> set[str]:
    """Парсит список CIDR/IP: по одной записи на строку. Возвращает множество строк 'ip' или 'ip/cidr'."""
    result = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Одна запись на строку: 1.2.3.4 или 1.2.3.4/24
        entry = line.split()[0] if line.split() else line
        try:
            if "/" in entry:
                ipaddress.ip_network(entry, strict=False)
                result.add(entry)
            else:
                ipaddress.ip_address(entry)
                result.add(entry)
        except ValueError:
            continue
    return result


def setup_iptables(allowed_destinations: set[str]) -> None:
    """Разрешить только исходящие соединения к allowed_destinations (IP или CIDR), localhost и DNS.
    Использует iptables-restore для быстрой загрузки десятков тысяч правил одним вызовом."""
    lines = [
        "*filter",
        ":OUTPUT ACCEPT [0:0]",
        "-F OUTPUT",
        "-P OUTPUT DROP",
        "-A OUTPUT -o lo -j ACCEPT",
        "-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
    ]
    for dns_ip in ("8.8.8.8", "8.8.4.4", "1.1.1.1"):
        lines.append(f"-A OUTPUT -p udp --dport 53 -d {dns_ip} -j ACCEPT")
    for dest in sorted(allowed_destinations):
        if dest:
            lines.append(f"-A OUTPUT -d {dest} -j ACCEPT")
    lines.append("COMMIT")
    script = "\n".join(lines) + "\n"
    proc = subprocess.run(
        ["iptables-restore", "--noflush"],
        input=script.encode(),
        capture_output=True,
        timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"iptables-restore failed: {proc.stderr.decode(errors='replace')}")


def main():
    mode = (os.environ.get("MODE", "single") or "single").strip().lower()
    list_url = (
        (sys.argv[1] if len(sys.argv) > 1 and sys.argv[1].startswith("http") else None)
        or os.environ.get("DEFAULT_LIST_URL", "")
    )

    if mode == "merge":
        links_path = LINKS_FILE if os.path.isfile(LINKS_FILE) else os.path.join("/app", LINKS_FILE)
        if not os.path.isfile(links_path):
            print(f"Ошибка: файл со ссылками не найден: {links_path}", file=sys.stderr)
            sys.exit(1)
        with open(links_path, encoding="utf-8") as f:
            urls = []
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Разбиваем строку по пробелам и берем только валидные URL
                parts = line.split()
                for part in parts:
                    part = part.strip()
                    # Проверяем, что это похоже на URL
                    if part.startswith(("http://", "https://")):
                        urls.append(part)
        if not urls:
            print("В файле со ссылками нет URL.", file=sys.stderr)
            sys.exit(1)
        print(f"Режим merge: объединение ключей из {len(urls)} ссылок (до применения ограничений)...")
        try:
            keys_text = merge_keys_from_urls(urls)
        except Exception as e:
            print(f"Ошибка загрузки списков: {e}", file=sys.stderr)
            sys.exit(1)
        list_file = "/tmp/vless_keys_list.txt"
        with open(list_file, "w", encoding="utf-8") as f:
            f.write(keys_text)
        list_url = list_file
        os.environ["MODE"] = "single"
    elif not list_url:
        print("DEFAULT_LIST_URL не задан, пропуск настройки firewall.", file=sys.stderr)
        os.execvp("python", ["python", "vless_checker.py"] + sys.argv[1:])
        return
    else:
        print("Загрузка списка ключей (до применения ограничений)...")
        try:
            keys_text = fetch(list_url)
        except Exception as e:
            print(f"Ошибка загрузки списка ключей: {e}", file=sys.stderr)
            sys.exit(1)
        list_file = "/tmp/vless_keys_list.txt"
        with open(list_file, "w", encoding="utf-8") as f:
            f.write(keys_text)

    print("Загрузка CIDR whitelist...")
    try:
        cidr_text = fetch(CIDR_WHITELIST_URL)
    except Exception as e:
        print(f"Ошибка загрузки CIDR whitelist: {e}", file=sys.stderr)
        sys.exit(1)
    cidr_entries = parse_cidr_whitelist(cidr_text)
    print(f"Записей CIDR в белом списке: {len(cidr_entries)}")

    allowed_destinations = cidr_entries
    print(f"Разрешённых назначений (только CIDR whitelist): {len(allowed_destinations)}")

    print("Применение iptables (только CIDR whitelist)...")
    try:
        setup_iptables(allowed_destinations)
    except Exception as e:
        print(f"Ошибка iptables (нужен cap NET_ADMIN): {e}", file=sys.stderr)
        sys.exit(1)

    print("Запуск vless_checker.py (список из файла)...")
    script_args = ["python", "vless_checker.py", list_file]
    for a in sys.argv[1:]:
        if a.startswith("-"):
            script_args.append(a)
    ret = subprocess.run(script_args)
    if ret.returncode != 0:
        sys.exit(ret.returncode)

    # Speedtest внутри контейнера (те же ограничения CIDR).
    # Читаем список конфигов, которые только что записал vless_checker выше (configs/white-list_available).
    speedtest_enabled = os.environ.get("SPEED_TEST_ENABLED", "").strip().lower() in ("true", "1", "yes")
    wl_path = os.path.join("/app", "configs", "white-list_available")
    if speedtest_enabled and os.path.isfile(wl_path) and os.path.getsize(wl_path) > 0:
        print("Запуск speedtest_checker.py по white-list_available...")
        ret2 = subprocess.run(["python", "speedtest_checker.py", wl_path], env=os.environ)
        if ret2.returncode == 0:
            configs = os.path.join("/app", "configs")
            st_out = os.path.join(configs, "white-list_available_st")
            st_top = os.path.join(configs, "white-list_available_st(top100)")
            wl_top = os.path.join(configs, "white-list_available(top100)")
            if os.path.isfile(st_out) and os.path.getsize(st_out) > 0:
                os.replace(st_out, wl_path)
                if os.path.isfile(st_top):
                    os.replace(st_top, wl_top)
                else:
                    with open(wl_path, "r", encoding="utf-8") as f:
                        lines = f.readlines()[:100]
                    with open(wl_top, "w", encoding="utf-8") as f:
                        f.writelines(lines)
                print("Результат speedtest записан в white-list_available и white-list_available(top100).")
        else:
            print("Speedtest завершился с ошибкой или без результатов, оставляем вывод checker.", file=sys.stderr)
    sys.exit(0)


if __name__ == "__main__":
    main()
