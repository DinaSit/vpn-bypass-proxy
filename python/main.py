import os
import select
import socket
import subprocess
import threading
import time
from urllib.parse import urlparse

# Прокси доступен локально на порту 18080
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 18080


def detect_wifi_interface() -> str:
    """
    Порядок определения сетевого интерфейса Wi-Fi на macOS:
    1. значение переменной окружения BYPASS_IFACE;
    2. автоматическое определение через networksetup;
    3. fallback на en0.
    """
    env_iface = os.getenv("BYPASS_IFACE")
    if env_iface:
        return env_iface

    try:
        result = subprocess.run(
            ["networksetup", "-listallhardwareports"],
            capture_output=True,
            text=True,
            check=True,
        )
    except Exception:
        return "en0"

    blocks = result.stdout.split("\n\n")

    for block in blocks:
        lines = block.splitlines()

        is_wifi_block = any(
            line.strip() in {"Hardware Port: Wi-Fi", "Hardware Port: AirPort"}
            for line in lines
        )

        if not is_wifi_block:
            continue

        for line in lines:
            line = line.strip()
            if line.startswith("Device:"):
                return line.split(":", 1)[1].strip()

    return "en0"


# Номера опций «привязать соединение к интерфейсу» из заголовков macOS:
# IPv4 → IP_BOUND_IF (25), IPv6 → IPV6_BOUND_IF (125).
BOUND_IF = {
    socket.AF_INET:  (socket.IPPROTO_IP,   25),
    socket.AF_INET6: (socket.IPPROTO_IPV6, 125),
}

# Интерфейс, через который выполняется обход VPN.
# По умолчанию определяется автоматически как Wi-Fi-интерфейс macOS.
IFACE = detect_wifi_interface()


def should_bypass_vpn(host: str | None) -> bool:
    """
    Определяет, должен ли домен обходить VPN.

    .ru и .рф направляются через IFACE,
    остальные домены используют системный маршрут по умолчанию.
    """
    if not host:
        return False

    host = host.lower()
    return host.endswith(".ru") or host.endswith(".xn--p1ai") # .рф в Punycode


def open_socket(host: str, port: int, bypass_vpn: bool) -> socket.socket:
    """
    Создаёт TCP-соединение с удалённым узлом (Happy Eyeballs).

    Резолвит host в список адресов (IPv4 и IPv6), пробует подключиться
    ко всем сразу и возвращает первый успешный. При bypass_vpn=True каждое
    соединение привязывается к IFACE (мимо VPN).
    """
    candidates = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)

    # 1. Запускаем неблокирующий connect на каждый адрес сразу
    pending = []
    for family, socktype, proto, _, addr in candidates:
        s = socket.socket(family, socktype, proto)
        try:
            s.setblocking(False)
            if bypass_vpn:
                level, optname = BOUND_IF[family]
                s.setsockopt(level, optname, socket.if_nametoindex(IFACE))
            s.connect_ex(addr)
        except BaseException:
            # упало на настройке (например, интерфейс исчез) —
            # закрываем этот и все уже запущенные сокеты, чтобы не текло
            s.close()
            for p in pending:
                p.close()
            raise
        pending.append(s)

    # 2. Ждём, кто первым подключится (сокет становится writable по завершении connect)
    deadline = time.monotonic() + 15
    winner = None
    while pending and winner is None:
        timeout = deadline - time.monotonic()
        if timeout <= 0:
            break
        _, writable, _ = select.select([], pending, [], timeout)
        for s in writable:
            err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if err == 0:
                winner = s
                break
            s.close()
            pending.remove(s)

    # 3. Закрываем остальных
    for s in pending:
        if s is not winner:
            s.close()

    if winner is None:
        raise OSError(f"не удалось подключиться ни к одному адресу {host}:{port}")

    winner.setblocking(True)
    winner.settimeout(15)
    return winner


def relay(a: socket.socket, b: socket.socket):
    """
    Передаёт данные между клиентским и upstream-сокетом.

    Используется для HTTPS CONNECT-туннеля.
    TLS-трафик не расшифровывается и не модифицируется.
    """
    sockets = [a, b]

    while True:
        # select.select() возвращает три списка сокетов:
        # readable - готовые к чтению,
        # writable - готовые к записи (не используется),
        # errored - с ошибками
        readable, _, errored = select.select(sockets, [], sockets, 60)

        if errored:
            break

        if not readable:
            break

        for src in readable:
            # Определяем, какой сокет является источником, а какой - приёмником
            dst = b if src is a else a

            try:
                # Читаем данные из источника и отправляем их в приёмник
                data = src.recv(65536)
                if not data:
                    return
                dst.sendall(data)
            except Exception:
                return


def handle_connect(client: socket.socket, target: str):
    """
    Обрабатывает HTTPS-запросы через метод CONNECT.

    После успешного подключения к upstream-серверу прокси создаёт туннель
    и передаёт дальнейший обмен без анализа содержимого.
    """
    if ":" in target:
        host, port_str = target.rsplit(":", 1)
        port = int(port_str)
    else:
        host = target
        port = 443

    bypass = should_bypass_vpn(host)
    route = "BYPASS_VPN_VIA_WIFI" if bypass else "DEFAULT_VPN"

    print(f"[https host] {host}")
    print(f"[route] {route}")

    upstream = open_socket(host, port, bypass)
    try:
        client.sendall(
            b"HTTP/1.1 200 Connection Established\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        relay(client, upstream)
    finally:
        upstream.close()


def handle_http(client: socket.socket, data: bytes):
    """
    Обрабатывает обычный HTTP-запрос в proxy-формате.

    Абсолютный URL из первой строки запроса преобразуется в origin-form
    перед отправкой на upstream-сервер
    * не сильно паримся, потому что http не оч нужен, и большинство сайтов уже используют https
    """
    header, _, body = data.partition(b"\r\n\r\n")
    lines = header.split(b"\r\n")

    first_line = lines[0].decode("latin1", errors="replace")
    method, target, version = first_line.split()

    parsed = urlparse(target)

    host = parsed.hostname
    port = parsed.port or 80
    path = parsed.path or "/"

    if parsed.query:
        path += "?" + parsed.query

    bypass = should_bypass_vpn(host)
    route = "BYPASS_VPN_VIA_WIFI" if bypass else "DEFAULT_VPN"

    print(f"[http host] {host}")
    print(f"[route] {route}")

    # Преобразуем первую строку запроса в origin-form
    new_first_line = f"{method} {path} {version}".encode("latin1")
    # Убираем заголовки Connection и Proxy-Connection, 
    # чтобы upstream-сервер не пытался поддерживать соединение открытым
    kept = [
        line for line in lines[1:]
        if not line.lower().startswith((b"connection:", b"proxy-connection:"))
    ]
    kept.append(b"Connection: close")
    # хороший keep-alive потребовал бы разбор ответа сервера, chunked-декодер, цикл и обработку краевых случаев, 
    # но мне лень, так что просто закрываем соединение после каждого запроса

    # Собираем новый заголовок и тело запроса
    # Сколько тела обещано в заголовках:
    content_length = 0
    for line in lines[1:]:
        if line.lower().startswith(b"content-length:"):
            content_length = int(line.split(b":", 1)[1])
            break

    # Тело могло прийти не целиком (один recv в handle_client берёт максимум 64КБ и только те пакеты, что уже дошли) 
    # Дочитываем, пока не наберём полный Content-Length
    while len(body) < content_length:
        chunk = client.recv(65536)
        if not chunk:
            break
        body += chunk

    # Теперь тело целиком — собираем запрос и отправляем на upstream-сервер
    new_header = b"\r\n".join([new_first_line] + kept)
    new_data = new_header + b"\r\n\r\n" + body

    upstream = open_socket(host, port, bypass)
    try:
        upstream.sendall(new_data)
        while True:
            chunk = upstream.recv(65536)
            if not chunk:
                break
            client.sendall(chunk)
    finally:
        upstream.close()


def handle_client(client: socket.socket):
    """
    Обрабатывает одно входящее соединение от браузера.

    Поддерживаются CONNECT-запросы для HTTPS и обычные HTTP proxy-запросы.
    """
    try:
        data = client.recv(65536)
        if not data:
            return

        first_line = data.split(b"\r\n", 1)[0].decode("latin1", errors="replace")
        parts = first_line.split()

        if len(parts) < 3:
            return

        method = parts[0]
        target = parts[1]

        if method.upper() == "CONNECT":
            handle_connect(client, target)
        else:
            handle_http(client, data)

    except Exception as e:
        print(f"[error] {e}")
        try:
            client.sendall(
                b"HTTP/1.1 502 Bad Gateway\r\n"
                b"Content-Type: text/plain\r\n"
                b"Connection: close\r\n"
                b"\r\n"
                b"Proxy error\n"
            )
        except Exception:
            pass
    finally:
        client.close()


def main():
    """
    Инициализирует локальный прокси-сервер.

    Каждое клиентское соединение обрабатывается в отдельном daemon-потоке.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_HOST, LISTEN_PORT))
    server.listen(100)

    print(f"Proxy listening on {LISTEN_HOST}:{LISTEN_PORT}")
    print("Press Ctrl+C to stop")

    try:
        while True:
            try:
                client, _ = server.accept()
            except OSError as e:
                print(f"[error] accept: {e}")
                time.sleep(0.1)   # дать дескрипторам освободиться
                continue
            threading.Thread(target=handle_client, args=(client,), daemon=True).start()
    except KeyboardInterrupt:
        print("\nProxy stopped")
    finally:
        server.close()


if __name__ == "__main__":
    main()
