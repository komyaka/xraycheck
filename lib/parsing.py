#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Модуль парсинга прокси URL (VLESS, VMess, Trojan, Shadowsocks, Hysteria, Hysteria2) и загрузки списков ключей.
"""

import base64
import json
import os
import requests
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs, unquote

from .config import OUTPUT_ADD_DATE, OUTPUT_DIR, OUTPUT_FILE
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
)

console = Console()

_MAX_CASCADE_DEPTH = 3
_MAX_ERROR_MSG_LENGTH = 200


def get_source_name(url_or_path: str) -> str:
    """Имя источника: последний сегмент URL path или basename файла без расширения."""
    if url_or_path.startswith("http://") or url_or_path.startswith("https://"):
        path = urlparse(url_or_path).path.rstrip("/")
        return path.split("/")[-1] if path else "list"
    return os.path.splitext(os.path.basename(url_or_path))[0] or "list"


def get_output_path(list_url: str) -> str:
    """Путь к файлу результата: OUTPUT_DIR/имя; при OUTPUT_ADD_DATE=false - OUTPUT_FILE как есть; иначе база + (источник_ДДММГГГГ).txt."""
    if not OUTPUT_ADD_DATE:
        base, ext = os.path.splitext(OUTPUT_FILE)
        name = f"{base or 'available'}{ext}"
    else:
        base, ext = os.path.splitext(OUTPUT_FILE)
        base = base or "available"
        ext = ext or ".txt"
        source = get_source_name(list_url)
        date = datetime.now().strftime("%d%m%Y")
        name = f"{base} ({source}_{date}){ext}"
    return os.path.join(OUTPUT_DIR, name) if OUTPUT_DIR else name


# Префиксы протоколов для проверки «уже раскодировано»
_SUBSCRIPTION_PROTOCOLS = ("vless://", "vmess://", "trojan://", "ss://", "hysteria://", "hysteria2://", "hy2://")


def normalize_proxy_link(link: str) -> str:
    """
    Возвращает ключ без фрагмента (всё после # - комментарий к ключу).
    Дедупликация notworkers и сравнение выполняются только по нормализованному ключу:
    два ключа считаются одним и тем же, если normalize_proxy_link(a) == normalize_proxy_link(b).
    """
    link = link.strip().split(maxsplit=1)[0]
    if "#" in link:
        link = link.split("#", 1)[0].strip()
    return link


def load_notworkers(path: str) -> set[str]:
    """
    Читает файл с неактивными ключами (один ключ на строку).
    Возвращает множество нормализованных ссылок (без фрагмента #комментарий) для фильтрации и дедупликации.
    Пустые строки и строки-комментарии (# в начале) пропускаются. Если файла нет - пустое множество.
    Сравнение при фильтрации - по нормализованному ключу (полное совпадение ключа без комментария).
    """
    normalized_set, _ = load_notworkers_with_lines(path)
    return normalized_set


def load_notworkers_with_lines(path: str) -> tuple[set[str], dict[str, str]]:
    """
    Читает файл с неактивными ключами (один ключ на строку).
    Возвращает (множество нормализованных ссылок, отображение нормализованный_ключ -> полная_строка).
    Полная строка сохраняется как в файле (с комментарием после # и т.д.) для записи без обрезки.
    """
    result: set[str] = set()
    normalized_to_full: dict[str, str] = {}
    if not os.path.isfile(path):
        return result, normalized_to_full
    with open(path, encoding="utf-8") as f:
        for line in f:
            full_line = line.strip()
            if not full_line or full_line.startswith("#"):
                continue
            link = full_line.split(maxsplit=1)[0].strip()
            if link and any(link.startswith(p) for p in _SUBSCRIPTION_PROTOCOLS):
                norm = normalize_proxy_link(link)
                result.add(norm)
                normalized_to_full[norm] = full_line
    return result, normalized_to_full


def save_notworkers(path: str, normalized_to_full: dict[str, str]) -> None:
    """Записывает неактивные ключи в файл как есть (полная строка на каждую запись), отсортировано по нормализованному ключу для стабильного diff."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for norm in sorted(normalized_to_full):
            full_line = normalized_to_full[norm]
            if full_line:
                f.write(full_line + "\n")


def load_keys_from_file(path: str) -> list[tuple[str, str]]:
    """
    Читает файл с прокси-ключами (один на строку). Возвращает список (ссылка, полная_строка).
    Пустые строки и строки, начинающиеся с #, пропускаются. Только строки с известным протоколом.
    """
    if not os.path.isfile(path):
        return []
    result: list[tuple[str, str]] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if any(line.startswith(p) for p in _SUBSCRIPTION_PROTOCOLS):
                link = line.split(maxsplit=1)[0].strip()
                if link:
                    result.append((link, line))
    return result


def _content_has_protocol_lines(text: str) -> bool:
    """Проверяет, есть ли в тексте строки, начинающиеся с известного протокола."""
    for line in text.splitlines():
        line = line.strip()
        if any(line.startswith(p) for p in _SUBSCRIPTION_PROTOCOLS):
            return True
    return False


def decode_subscription_content(text: str) -> str:
    """
    Декодирует контент подписки: если текст - base64 (типично для ссылок вроде nowmeow.pw/.../whitelist
    или gitverse.ru/.../whitelist.txt), возвращает раскодированный текст. Иначе возвращает исходный.
    """
    if not text or not text.strip():
        return text
    text = text.strip()
    # Уже есть ссылки с протоколами - не трогаем
    if _content_has_protocol_lines(text):
        return text
    # Убираем переносы строк внутри base64 (некоторые серверы отдают с переносами)
    raw = "".join(text.split())
    for encoding in (base64.standard_b64decode, base64.urlsafe_b64decode):
        try:
            padded = raw
            if len(padded) % 4:
                padded += "=" * (4 - len(padded) % 4)
            decoded = encoding(padded)
            if isinstance(decoded, bytes):
                decoded = decoded.decode("utf-8", errors="replace")
            decoded = decoded.strip()
            if decoded and _content_has_protocol_lines(decoded):
                return decoded
        except Exception:
            continue
    return text


def fetch_list(url: str) -> str:
    """Загружает текст списка по URL. Поддерживает ответ в base64 (формат подписок)."""
    # Валидация URL перед использованием
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Некорректный URL: {url}")
        # Проверка на управляющие символы
        if any(ord(c) < 32 and c not in '\t\n\r' for c in url):
            raise ValueError(f"URL содержит управляющие символы: {url}")
    except Exception as e:
        raise ValueError(f"Ошибка валидации URL: {e}")
    
    r = requests.get(url, timeout=15)
    r.raise_for_status()
    return decode_subscription_content(r.text)


def load_urls_from_file(path: str) -> list[str]:
    """Читает файл с URL (по одному на строку), возвращает список непустых URL.
    Обрабатывает случаи, когда в строке несколько URL, разделенных пробелами."""
    urls = []
    with open(path, encoding="utf-8") as f:
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
    return urls


def parse_proxy_lines(text: str) -> list[tuple[str, str]]:
    """Возвращает список (прокси_ссылка, полная_строка) для строк с поддерживаемыми протоколами."""
    supported_protocols = ("vless://", "vmess://", "trojan://", "ss://", "hysteria://", "hysteria2://", "hy2://")
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


# Обратная совместимость
def parse_vless_lines(text: str) -> list[tuple[str, str]]:
    """Устаревшая функция, используйте parse_proxy_lines. Оставлена для совместимости."""
    return parse_proxy_lines(text)


def parse_vless_url(vless_url: str) -> dict | None:
    """
    Парсит vless://uuid@host:port?query#fragment.
    Возвращает словарь для построения конфига xray или None при ошибке.
    """
    try:
        parsed = urlparse(vless_url)
        if parsed.scheme != "vless" or not parsed.netloc:
            return None
        netloc = parsed.netloc
        if "@" not in netloc:
            return None
        userinfo, host_port = netloc.rsplit("@", 1)
        uuid = userinfo
        if ":" in host_port:
            host, _, port_str = host_port.rpartition(":")
            port = int(port_str)
        else:
            host, port = host_port, 443
        if not host or not uuid:
            return None

        query = parse_qs(parsed.query or "", keep_blank_values=True)

        def get(name: str, default: str = "") -> str:
            a = query.get(name, [default])
            return (a[0] or default).strip()

        network = get("type", "tcp").lower()
        security = get("security", "reality").lower()
        flow = get("flow", "")
        fp = get("fp", "chrome")
        pbk = get("pbk", "")
        sid = get("sid", "")
        sni = get("sni", "")
        mode = get("mode", "")  # для xhttp: mode=auto

        return {
            "protocol": "vless",
            "uuid": uuid,
            "address": host,
            "port": port,
            "network": network,
            "security": security,
            "flow": flow,
            "fingerprint": fp,
            "publicKey": pbk,
            "shortId": sid,
            "serverName": sni,
            "mode": mode,
        }
    except Exception:
        return None


def parse_vmess_url(vmess_url: str) -> dict | None:
    """
    Парсит vmess://base64(json) или vmess://userInfo@host:port?params.
    Возвращает словарь для построения конфига xray или None при ошибке.
    """
    try:
        parsed = urlparse(vmess_url)
        if parsed.scheme != "vmess" or not parsed.netloc:
            return None
        
        # Попытка 1: base64-encoded JSON формат (vmess://base64)
        if "@" not in parsed.netloc:
            try:
                # Убираем схему и декодируем base64
                base64_part = vmess_url.replace("vmess://", "").split("#")[0]
                # Добавляем padding если нужно
                padding = 4 - len(base64_part) % 4
                if padding != 4:
                    base64_part += "=" * padding
                decoded = base64.urlsafe_b64decode(base64_part).decode("utf-8")
                vmess_json = json.loads(decoded)
                
                # Извлекаем данные из JSON
                address = vmess_json.get("add", "")
                port = int(vmess_json.get("port", 443))
                user_id = vmess_json.get("id", "")
                alter_id = int(vmess_json.get("aid", 0))
                security = vmess_json.get("scy", "auto").lower()
                network = vmess_json.get("net", "tcp").lower()
                tls = vmess_json.get("tls", "").lower()
                sni = vmess_json.get("sni", "")
                
                # Параметры для разных типов сетей
                ws_path = vmess_json.get("path", "")
                ws_host = vmess_json.get("host", "")
                grpc_service_name = vmess_json.get("ps", "")
                
                return {
                    "protocol": "vmess",
                    "address": address,
                    "port": port,
                    "id": user_id,
                    "alterId": alter_id,
                    "security": security,
                    "network": network,
                    "tls": tls,
                    "serverName": sni,
                    "wsPath": ws_path,
                    "wsHost": ws_host,
                    "grpcServiceName": grpc_service_name,
                }
            except Exception:
                pass
        
        # Попытка 2: URL формат (vmess://userInfo@host:port?params)
        netloc = parsed.netloc
        if "@" in netloc:
            userinfo, host_port = netloc.rsplit("@", 1)
            if ":" in host_port:
                host, _, port_str = host_port.rpartition(":")
                port = int(port_str)
            else:
                host, port = host_port, 443
            
            query = parse_qs(parsed.query or "", keep_blank_values=True)
            def get(name: str, default: str = "") -> str:
                a = query.get(name, [default])
                return (a[0] or default).strip()
            
            # Декодируем userinfo (может быть base64)
            try:
                userinfo_decoded = base64.urlsafe_b64decode(userinfo + "==").decode("utf-8")
                if ":" in userinfo_decoded:
                    user_id, alter_id_str = userinfo_decoded.split(":", 1)
                    alter_id = int(alter_id_str) if alter_id_str.isdigit() else 0
                else:
                    user_id = userinfo_decoded
                    alter_id = 0
            except Exception:
                user_id = userinfo
                alter_id = 0
            
            network = get("network", "tcp").lower()
            tls = get("tls", "").lower()
            sni = get("sni", "")
            ws_path = get("wsPath", "")
            ws_host = get("wsHost", "")
            
            return {
                "protocol": "vmess",
                "address": host,
                "port": port,
                "id": user_id,
                "alterId": alter_id,
                "security": "auto",
                "network": network,
                "tls": tls,
                "serverName": sni,
                "wsPath": ws_path,
                "wsHost": ws_host,
            }
        
        return None
    except Exception:
        return None


def parse_trojan_url(trojan_url: str) -> dict | None:
    """
    Парсит trojan://password@host:port?params#tag.
    Возвращает словарь для построения конфига xray или None при ошибке.
    """
    try:
        parsed = urlparse(trojan_url)
        if parsed.scheme != "trojan" or not parsed.netloc:
            return None
        
        netloc = parsed.netloc
        if "@" not in netloc:
            return None
        
        password, host_port = netloc.rsplit("@", 1)
        password = unquote(password)
        
        if ":" in host_port:
            host, _, port_str = host_port.rpartition(":")
            port = int(port_str)
        else:
            host, port = host_port, 443
        
        if not host or not password:
            return None
        
        query = parse_qs(parsed.query or "", keep_blank_values=True)
        def get(name: str, default: str = "") -> str:
            a = query.get(name, [default])
            return (a[0] or default).strip()
        
        network = get("type", "tcp").lower()
        sni = get("sni", "")
        ws_path = get("wsPath", "")
        ws_host = get("host", "")
        grpc_service_name = get("serviceName", "")
        
        return {
            "protocol": "trojan",
            "address": host,
            "port": port,
            "password": password,
            "network": network,
            "serverName": sni,
            "wsPath": ws_path,
            "wsHost": ws_host,
            "grpcServiceName": grpc_service_name,
        }
    except Exception:
        return None


def parse_hysteria_url(hysteria_url: str) -> dict | None:
    """
    Парсит hysteria://host:port?protocol=udp&auth=...&peer=... (Hysteria v1, Shadowrocket-стиль).
    Возвращает словарь с полями для идентификации и проверки; Xray не поддерживает Hysteria.
    """
    try:
        parsed = urlparse(hysteria_url)
        if parsed.scheme != "hysteria" or not parsed.netloc:
            return None
        host_port = parsed.netloc
        if ":" in host_port:
            host, _, port_str = host_port.rpartition(":")
            port = int(port_str)
        else:
            host, port = host_port, 443
        if not host:
            return None
        query = parse_qs(parsed.query or "", keep_blank_values=True)
        def get(name: str, default: str = "") -> str:
            a = query.get(name, [default])
            return (a[0] or default).strip()
        return {
            "protocol": "hysteria",
            "address": host,
            "port": port,
            "auth": get("auth", ""),
            "peer": get("peer", ""),
            "insecure": get("insecure", ""),
            "obfs": get("obfs", ""),
            "obfsParam": get("obfsParam", ""),
            "alpn": get("alpn", "hysteria"),
        }
    except Exception:
        return None


def parse_hysteria2_url(hysteria2_url: str) -> dict | None:
    """
    Парсит hysteria2://[auth@]hostname[:port]/?params или hy2:// (Hysteria 2).
    Возвращает словарь с полями для идентификации; Xray не поддерживает Hysteria2.
    """
    try:
        # Нормализуем схему: hy2 -> hysteria2
        url = hysteria2_url.strip()
        if url.startswith("hy2://"):
            url = "hysteria2://" + url[6:]
        parsed = urlparse(url)
        if parsed.scheme != "hysteria2" or not parsed.hostname:
            return None
        host = parsed.hostname or ""
        port = parsed.port if parsed.port is not None else 443
        auth = (parsed.username or "")
        if parsed.password:
            auth = f"{parsed.username or ''}:{parsed.password}"
        query = parse_qs(parsed.query or "", keep_blank_values=True)
        def get(name: str, default: str = "") -> str:
            a = query.get(name, [default])
            return (a[0] or default).strip()
        return {
            "protocol": "hysteria2",
            "address": host,
            "port": port,
            "auth": auth,
            "sni": get("sni", ""),
            "insecure": get("insecure", ""),
            "obfs": get("obfs", ""),
            "obfsPassword": get("obfs-password", ""),
            "pinSHA256": get("pinSHA256", ""),
        }
    except Exception:
        return None


def parse_shadowsocks_url(ss_url: str) -> dict | None:
    """
    Парсит ss://base64(method:password)@host:port или ss://method:password@host:port.
    Возвращает словарь для построения конфига xray или None при ошибке.
    """
    try:
        parsed = urlparse(ss_url)
        if parsed.scheme != "ss" or not parsed.netloc:
            return None
        
        netloc = parsed.netloc
        method = ""
        password = ""
        
        if "@" in netloc:
            userinfo, host_port = netloc.rsplit("@", 1)
            
            # Попытка декодировать base64
            try:
                padding = 4 - len(userinfo) % 4
                if padding != 4:
                    userinfo += "=" * padding
                decoded = base64.urlsafe_b64decode(userinfo).decode("utf-8")
                if ":" in decoded:
                    method, password = decoded.split(":", 1)
                else:
                    method = decoded
            except Exception:
                # Если не base64, пробуем как plain text
                if ":" in userinfo:
                    method, password = userinfo.split(":", 1)
                else:
                    method = userinfo
            
            if ":" in host_port:
                host, _, port_str = host_port.rpartition(":")
                port = int(port_str)
            else:
                host, port = host_port, 8388
        else:
            # Старый формат: ss://base64(method:password@host:port)
            try:
                base64_part = ss_url.replace("ss://", "").split("#")[0]
                padding = 4 - len(base64_part) % 4
                if padding != 4:
                    base64_part += "=" * padding
                decoded = base64.urlsafe_b64decode(base64_part).decode("utf-8")
                if "@" in decoded:
                    userinfo, host_port = decoded.rsplit("@", 1)
                    if ":" in userinfo:
                        method, password = userinfo.split(":", 1)
                    else:
                        method = userinfo
                    if ":" in host_port:
                        host, _, port_str = host_port.rpartition(":")
                        port = int(port_str)
                    else:
                        host, port = host_port, 8388
                else:
                    return None
            except Exception:
                return None
        
        if not host or not method or not password:
            return None
        
        return {
            "protocol": "shadowsocks",
            "address": host,
            "port": port,
            "method": method,
            "password": password,
        }
    except Exception:
        return None


def parse_proxy_url(proxy_url: str) -> dict | None:
    """
    Универсальный парсер прокси URL. Определяет протокол и вызывает соответствующий парсер.
    Поддерживает: VLESS, VMess, Trojan, Shadowsocks, Hysteria, Hysteria2.
    Возвращает словарь для построения конфига xray (или для проверки) или None при ошибке.
    """
    if not proxy_url:
        return None
    
    proxy_url = proxy_url.strip()
    
    if proxy_url.startswith("vless://"):
        return parse_vless_url(proxy_url)
    elif proxy_url.startswith("vmess://"):
        return parse_vmess_url(proxy_url)
    elif proxy_url.startswith("trojan://"):
        return parse_trojan_url(proxy_url)
    elif proxy_url.startswith("ss://"):
        return parse_shadowsocks_url(proxy_url)
    elif proxy_url.startswith("hysteria://"):
        return parse_hysteria_url(proxy_url)
    elif proxy_url.startswith("hysteria2://") or proxy_url.startswith("hy2://"):
        return parse_hysteria2_url(proxy_url)
    
    return None


def _is_url(value: str) -> bool:
    return value.startswith(("http://", "https://"))


def _normalize_source_identifier(source: str, base_dir: Path) -> str:
    """Нормализует источник для visited: URL как есть, пути -> абсолютные пути."""
    if _is_url(source):
        return source.strip()
    path = Path(source)
    if not path.is_absolute():
        path = (base_dir / path).resolve()
    else:
        path = path.resolve()
    return str(path)


def _looks_like_path(token: str) -> bool:
    """
    Грубая эвристика для выделения путей в каскадных файлах.
    Обрабатывает относительные/абсолютные пути с / или \\, а также имена файлов вроде file.txt.
    """
    if "://" in token:
        return False
    if token.startswith(("#", "//")):
        return False
    if any(sep in token for sep in ("/", "\\")):
        return True
    return token.endswith((".txt", ".list", ".urls", ".lst"))


def _log_cycle(source: str, reason: str = "cycle") -> None:
    postfix = "из-за цикла" if reason == "cycle" else "повтор"
    console.print(f"[yellow]Пропуск {postfix}:[/yellow] {source}")


def _depth_exceeded(depth: int, source: str) -> bool:
    if depth > _MAX_CASCADE_DEPTH:
        console.print(f"[yellow]Превышена глубина каскада ({_MAX_CASCADE_DEPTH}) для: {source}[/yellow]")
        return True
    return False


def _resolve_child_source(token: str, parent_source: str, base_dir: Path) -> str:
    """Резолвит дочерний источник относительно родителя (URL или файл)."""
    if _is_url(token):
        return token
    if _is_url(parent_source):
        return urljoin(parent_source, token)
    path = Path(token)
    if not path.is_absolute():
        path = (base_dir / path).resolve()
    else:
        path = path.resolve()
    return str(path)


def collect_sources(source: str, base_dir: Path, depth: int = 0, visited: set[str] | None = None) -> tuple[list[str], list[tuple[str, str]]]:
    """
    Читает один источник (URL или файл), возвращает (child_sources, keys).
    Использует visited и ограничение глубины для защиты от циклов.
    """
    if visited is None:
        visited = set()
    normalized = _normalize_source_identifier(source, base_dir)

    if normalized in visited:
        _log_cycle(source, reason="cycle")
        return [], []

    if _depth_exceeded(depth, source):
        return [], []

    visited.add(normalized)

    text: str
    current_base_dir = base_dir

    if _is_url(source):
        try:
            text = fetch_list(source)
        except Exception as e:
            raise ValueError(f"{source}: {e}") from e
    else:
        path = Path(source)
        if not path.is_absolute():
            path = (base_dir / path).resolve()
        else:
            path = path.resolve()
        if not path.exists():
            raise FileNotFoundError(f"Файл не найден: {path}")
        current_base_dir = path.parent
        with open(path, encoding="utf-8") as f:
            text = decode_subscription_content(f.read())

    keys = parse_proxy_lines(text)

    child_sources: list[str] = []
    seen_child: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        for part in parts:
            candidate = part.strip().strip(",;")
            if not candidate:
                continue
            if any(candidate.startswith(p) for p in _SUBSCRIPTION_PROTOCOLS):
                continue
            if _is_url(candidate) or _looks_like_path(candidate):
                resolved = _resolve_child_source(candidate, source, current_base_dir)
                if resolved not in seen_child:
                    seen_child.add(resolved)
                    child_sources.append(resolved)

    return child_sources, keys


def _gather_keys(initial_source: str, base_dir: Path, stop_on_error: bool) -> list[tuple[str, str]]:
    """Рекурсивный обход источников с дедупликацией ключей."""
    queue: list[tuple[str, Path, int]] = [(initial_source, base_dir, 0)]
    visited: set[str] = set()
    scheduled: set[str] = {_normalize_source_identifier(initial_source, base_dir)}
    seen_links: set[str] = set()
    result: list[tuple[str, str]] = []

    while queue:
        source, current_base, depth = queue.pop(0)
        scheduled.discard(_normalize_source_identifier(source, current_base))
        try:
            child_sources, keys = collect_sources(source, current_base, depth=depth, visited=visited)
        except Exception as e:
            if stop_on_error:
                raise
            error_msg = str(e)
            if len(error_msg) > _MAX_ERROR_MSG_LENGTH:
                error_msg = error_msg[:_MAX_ERROR_MSG_LENGTH - 3] + "..."
            console.print(f"[yellow]Пропуск источника:[/yellow] {source} -> {error_msg}")
            continue

        for link, full in keys:
            norm = normalize_proxy_link(link)
            if norm and norm not in seen_links:
                seen_links.add(norm)
                result.append((link, full))

        for child in child_sources:
            if _is_url(child):
                next_base = current_base
            else:
                next_base = Path(child).resolve().parent

            normalized_child = _normalize_source_identifier(child, next_base)
            next_depth = depth + 1
            if normalized_child in visited:
                _log_cycle(child, reason="cycle")
                continue
            if normalized_child in scheduled:
                _log_cycle(child, reason="duplicate")
                continue
            if _depth_exceeded(next_depth, child):
                continue

            scheduled.add(normalized_child)
            queue.append((child, next_base, next_depth))

    return result


def load_merged_keys(links_file: str) -> tuple[str, list[tuple[str, str]]]:
    """
    Режим merge: читает ссылки из links_file, загружает списки по каждой,
    объединяет ключи (дедупликация по ссылке, первое вхождение). Поддерживает
    каскадные источники (файлы/URL, содержащие ссылки на другие списки).
    Возвращает (имя_источника_для_вывода, список (proxy_ссылка, полная_строка)).
    """
    base_dir = Path(links_file).resolve().parent if not _is_url(links_file) else Path.cwd()

    keys = _gather_keys(links_file, base_dir, stop_on_error=False)
    if not keys:
        raise ValueError(f"В источнике {links_file} нет ключей или валидных ссылок")

    return ("merged", keys)


def load_keys_with_cascade(source: str) -> list[tuple[str, str]]:
    """
    Загружает ключи из источника (URL или локальный путь) с поддержкой каскада.
    Для одиночного режима ошибки загрузки приводят к исключению.
    """
    base_dir = Path(source).resolve().parent if not _is_url(source) else Path.cwd()
    return _gather_keys(source, base_dir, stop_on_error=True)
