import os
import select
import socket
import subprocess
import threading
from urllib.parse import urlparse

# Прокси доступен локально 
# Внешние устройства в сети не могут подключиться к 127.0.0.1.
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


# macOS-специфичная опция сокета.
# Используется для привязки исходящего IPv4-соединения к конкретному интерфейсу.
IP_BOUND_IF = 25

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
    return host.endswith(".ru") or host.endswith(".рф")


def open_socket(host: str, port: int, bypass_vpn: bool) -> socket.socket:
    """
    Создаёт TCP-соединение с удалённым узлом.

    При bypass_vpn=True соединение привязывается к IFACE.
    При bypass_vpn=False используется стандартная маршрутизация ОС.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(15)

    if bypass_vpn:
        idx = socket.if_nametoindex(IFACE)
        s.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, idx)

    s.connect((host, port))
    return s


def relay(a: socket.socket, b: socket.socket):
    """
    Передаёт данные между клиентским и upstream-сокетом.

    Используется для HTTPS CONNECT-туннеля.
    TLS-трафик не расшифровывается и не модифицируется.
    """
    a.setblocking(False)
    b.setblocking(False)

    sockets = [a, b]

    while True:
        readable, _, errored = select.select(sockets, [], sockets, 60)

        if errored:
            break

        if not readable:
            break

        for src in readable:
            dst = b if src is a else a

            try:
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
    route = "BYPASS_VPN_VIA_EN0" if bypass else "DEFAULT_VPN"

    print(f"[https host] {host}")
    print(f"[route] {route}")

    upstream = open_socket(host, port, bypass)

    client.sendall(
        b"HTTP/1.1 200 Connection Established\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )

    relay(client, upstream)
    upstream.close()


def handle_http(client: socket.socket, data: bytes):
    """
    Обрабатывает обычный HTTP-запрос в proxy-формате.

    Абсолютный URL из первой строки запроса преобразуется в origin-form
    перед отправкой на upstream-сервер.
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
    route = "BYPASS_VPN_VIA_EN0" if bypass else "DEFAULT_VPN"

    print(f"[http host] {host}")
    print(f"[route] {route}")

    new_first_line = f"{method} {path} {version}".encode("latin1")
    new_header = b"\r\n".join([new_first_line] + lines[1:])
    new_data = new_header + b"\r\n\r\n" + body

    upstream = open_socket(host, port, bypass)
    upstream.sendall(new_data)

    while True:
        chunk = upstream.recv(65536)
        if not chunk:
            break
        client.sendall(chunk)

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
            client, _ = server.accept()
            threading.Thread(target=handle_client, args=(client,), daemon=True).start()
    except KeyboardInterrupt:
        print("\nProxy stopped")
    finally:
        server.close()


if __name__ == "__main__":
    main()
