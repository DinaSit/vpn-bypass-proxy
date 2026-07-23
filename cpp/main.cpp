#include <arpa/inet.h>   // inet_pton — строка "127.0.0.1" → бинарный адрес
#include <fcntl.h>       // fcntl — переключение сокета в (не)блокирующий режим
#include <net/if.h>      // if_nametoindex — имя интерфейса "en0" → его номер
#include <netdb.h>       // getaddrinfo — резолв имени хоста в список адресов
#include <netinet/in.h>  // sockaddr_in, IPPROTO_* — структуры и константы IP
#include <signal.h>      // signal — чтобы погасить сигнал SIGPIPE (см. main)
#include <sys/select.h>  // select — "кто из сокетов готов?" (как в Python)
#include <sys/socket.h>  // socket, connect, send, recv, setsockopt — ядро всего
#include <unistd.h>      // close — закрыть файловый дескриптор (сокет)

#include <cerrno>        // errno — код последней системной ошибки
#include <cstdio>        // printf/popen
#include <cstring>       // strlen, memset
#include <ctime>         // time — для 15-секундного дедлайна в Happy Eyeballs
#include <mutex>         // std::mutex — чтобы потоки не путали строки в логе
#include <stdexcept>     // std::runtime_error — исключения вместо кодов ошибок
#include <string>
#include <thread>        // std::thread — по потоку на соединение
#include <vector>

// Настройки прокси
static const char* LISTEN_HOST = "127.0.0.1";
static const int   LISTEN_PORT = 18080;

// Лог из нескольких потоков
static std::mutex log_mutex;
static void log_line(const std::string& msg) {
    std::lock_guard<std::mutex> lock(log_mutex); // захватили — печатаем — отпустили
    std::printf("%s\n", msg.c_str());
    std::fflush(stdout); // сразу выталкиваем в файл, не копим в буфере
}

// ----------------------------------------------------------------------------
//  Определение Wi-Fi-интерфейса
//    1) переменная окружения BYPASS_IFACE;
//    2) вывод networksetup -listallhardwareports;
//    3) запасной вариант en0
// ----------------------------------------------------------------------------
static std::string detect_wifi_interface() {
    // getenv возвращает указатель на строку или nullptr, если переменной нет
    if (const char* env = std::getenv("BYPASS_IFACE"); env && *env)
        return env;

    // popen запускает внешнюю команду и даёт читать её вывод, как файл
    FILE* pipe = popen("networksetup -listallhardwareports", "r");
    if (!pipe)
        return "en0";

    std::string out;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), pipe)) > 0)
        out.append(buf, n);
    pclose(pipe);

    // Вывод разбит на блоки пустой строкой
    // Ищем блок с "Hardware Port: Wi-Fi" и достаём из него строку "Device: enX"
    size_t pos = 0;
    while (pos < out.size()) {
        size_t end = out.find("\n\n", pos);
        if (end == std::string::npos)
            end = out.size();
        std::string block = out.substr(pos, end - pos);
        pos = end + 2;

        if (block.find("Hardware Port: Wi-Fi") == std::string::npos &&
            block.find("Hardware Port: AirPort") == std::string::npos)
            continue;

        size_t dev = block.find("Device:");
        if (dev == std::string::npos)
            continue;
        size_t start = dev + 7; // длина слова "Device:"
        while (start < block.size() && block[start] == ' ')
            ++start; // пропускаем пробелы
        size_t stop = block.find('\n', start);
        return block.substr(start, stop == std::string::npos ? std::string::npos : stop - start);
    }
    return "en0";
}

// Интерфейс вычисляем один раз при старте и держим в глобальной переменной
static std::string IFACE = detect_wifi_interface();

// ----------------------------------------------------------------------------
//  bound_if_for — по семейству адреса выдаёт, ЧЕМ привязать сокет к интерфейсу
//    IPv4  → уровень IPPROTO_IP,   опция IP_BOUND_IF
//    IPv6  → уровень IPPROTO_IPV6, опция IPV6_BOUND_IF
// ----------------------------------------------------------------------------
static bool bound_if_for(int family, int& level, int& optname) {
    if (family == AF_INET)  { level = IPPROTO_IP;   optname = IP_BOUND_IF;   return true; }
    if (family == AF_INET6) { level = IPPROTO_IPV6; optname = IPV6_BOUND_IF; return true; }
    return false;
}

//  Должен ли домен обходить VPN
static bool should_bypass_vpn(std::string host) {
    // Приводим к нижнему регистру: RU и ru должны считаться одинаково.
    for (char& c : host)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    // ends_with появился в C++20 — прямой аналог Python-метода .endswith().
    return host.ends_with(".ru") || host.ends_with(".xn--p1ai");
}

// ----------------------------------------------------------------------------
//  send_all — отправить ВЕСЬ буфер
//  send() может отправить меньше, чем просили (столько, сколько влезло в буфер ядра)
//  Поэтому крутим цикл, сдвигая указатель, пока не уйдёт всё
// ----------------------------------------------------------------------------
static bool send_all(int fd, const char* data, size_t len) {
    while (len > 0) {
        ssize_t n = send(fd, data, len, 0);
        if (n <= 0)
            return false; // соединение оборвалось
        data += n;  // сдвигаем начало непосланного куска
        len  -= static_cast<size_t>(n);
    }
    return true;
}

// ----------------------------------------------------------------------------
//  open_socket — подключение к серверу по алгоритму Happy Eyeballs
//    1) резолвим имя в СПИСОК адресов (IPv4 и IPv6);
//    2) звоним на ВСЕ разом, не дожидаясь ответа (неблокирующий connect);
//    3) берём первого, кто реально дозвонился; остальных закрываем
//
//  Возвращает готовый сокет. Если не дозвонились никуда — бросает исключение
// ----------------------------------------------------------------------------
static int open_socket(const std::string& host, const std::string& port, bool bypass) {
    // Резолв имени
    // getaddrinfo с AF_UNSPEC = «дай и IPv4, и IPv6»
    addrinfo hints{}; // {} обнуляет все поля структуры
    hints.ai_family = AF_UNSPEC; // любое семейство
    hints.ai_socktype = SOCK_STREAM; // TCP

    addrinfo* res = nullptr; // список адресов
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0 || !res)
        throw std::runtime_error("getaddrinfo failed: " + host);

    // pending — «телефоны, которые сейчас звонят»
    std::vector<int> pending;

    // Лямбда-помощник: закрыть все pending и освободить список адресов
    // Вызовется при аварии, чтобы не текли сокеты
    auto cleanup_and_close = [&]() {
        for (int fd : pending)
            close(fd);
        freeaddrinfo(res);
    };

    // 1. Запускаем неблокирующий connect на каждый адрес
    for (addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) { // идём по списку
        int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0)
            continue;

        // Переводим сокет в НЕблокирующий режим: connect тогда не «висит»,
        // а сразу возвращает управление (звонок пошёл — идём дальше)
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        // Привязка к Wi-Fi мимо VPN — только для обходных доменов
        if (bypass) {
            int level, optname;
            unsigned int idx = if_nametoindex(IFACE.c_str()); // "en0" → номер
            if (!bound_if_for(ai->ai_family, level, optname) || idx == 0 ||
                setsockopt(fd, level, optname, &idx, sizeof(idx)) != 0) {
                // Настройка не удалась — закрываем этот сокет и всех уже запущенных
                close(fd);
                cleanup_and_close();
                throw std::runtime_error("bind to iface failed: " + IFACE);
            }
        }

        // Собственно «набор номера»
        // Для неблокирующего сокета connect почти всегда возвращает 
        // -1 с errno == EINPROGRESS — «звонок пошёл, ещё не соединилось»
        // Ошибка = любой другой errno
        int r = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (r != 0 && errno != EINPROGRESS) {
            close(fd); // этот адрес сразу отказал
            continue; // пробуем следующий
        }
        pending.push_back(fd); // «телефон звонит» — кладём в список
    }

    if (pending.empty()) { // ни одного адреса не завелось
        freeaddrinfo(res);
        throw std::runtime_error("no reachable address for " + host);
    }

    // 2. Ждём, кто первым дозвонится
    // Сокет становится «writable» (готов к записи), когда его connect завершился —
    // успехом ИЛИ ошибкой. Поэтому ждём готовности на ЗАПИСЬ, а не на чтение.
    time_t deadline = time(nullptr) + 15;
    int winner = -1;

    while (!pending.empty() && winner < 0) {
        time_t now = time(nullptr);
        if (now >= deadline)
            break; // время вышло

        fd_set wset; // набор сокетов «спросить про запись»
        FD_ZERO(&wset);
        int maxfd = -1;
        for (int fd : pending) {
            FD_SET(fd, &wset);
            if (fd > maxfd) maxfd = fd;
        }

        timeval tv{deadline - now, 0}; // ждать не дольше остатка времени
        int n = select(maxfd + 1, nullptr, &wset, nullptr, &tv);
        if (n <= 0)
            break;

        // Проходим по звонящим и ищем того, кто завершил connect УСПЕШНО
        for (size_t i = 0; i < pending.size();) {
            int fd = pending[i];
            if (!FD_ISSET(fd, &wset)) { // этот ещё не готов
                ++i;
                continue;
            }
            // «Дозвонился» != «ответили». Спрашиваем у сокета итог через SO_ERROR:
            // 0 → соединились, это победитель;
            // не 0 → линия мертва/занята, выкидываем
            int err = 0;
            socklen_t len = sizeof(err);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
            if (err == 0) {
                winner = fd; // первый успех — победитель
                break;
            }
            close(fd); // неудачный адрес — закрыть и убрать из списка (i не растёт)
            pending.erase(pending.begin() + i);
        }
    }

    freeaddrinfo(res); // список адресов больше не нужен

    // 3. Закрываем остальных
    for (int fd : pending)
        if (fd != winner)
            close(fd);

    if (winner < 0)
        throw std::runtime_error("could not connect to " + host);

    // Победителя возвращаем в обычный (блокирующий) режим и вешаем таймаут 15с
    // на чтение/запись — дальше по нему польётся обычный трафик
    int flags = fcntl(winner, F_GETFL, 0);
    fcntl(winner, F_SETFL, flags & ~O_NONBLOCK); // снять флаг O_NONBLOCK
    timeval tv{15, 0};
    setsockopt(winner, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(winner, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return winner;
}

// ----------------------------------------------------------------------------
//  relay — двунаправленный туннель для HTTPS (CONNECT)
//  Сокеты БЛОКИРУЮЩИЕ: select говорит, у кого есть данные, а recv/send на готовом сокете отработают штатно
// ----------------------------------------------------------------------------
static void relay(int a, int b) {
    while (true) {
        fd_set rset, eset; // готовые к чтению / с ошибкой
        FD_ZERO(&rset);
        FD_ZERO(&eset);
        FD_SET(a, &rset); FD_SET(b, &rset);
        FD_SET(a, &eset); FD_SET(b, &eset);
        int maxfd = (a > b) ? a : b;

        timeval tv{60, 0}; // 60с тишины = закрываем туннель
        int n = select(maxfd + 1, &rset, nullptr, &eset, &tv);
        if (n <= 0)
            break; // таймаут простоя или ошибка select
        if (FD_ISSET(a, &eset) || FD_ISSET(b, &eset))
            break; // ошибка на сокете

        // src — тот, у кого есть данные;
        // dst — противоположная сторона
        for (int src : {a, b}) {
            if (!FD_ISSET(src, &rset))
                continue;
            int dst = (src == a) ? b : a;

            char buf[65536];
            ssize_t r = recv(src, buf, sizeof(buf), 0);
            if (r <= 0)
                return; // сторона закрылась — туннель окончен
            if (!send_all(dst, buf, static_cast<size_t>(r)))
                return;
        }
    }
}

// Строковые помощники
static std::vector<std::string> split_lines(const std::string& s) {
    std::vector<std::string> lines;
    size_t pos = 0;
    while (pos <= s.size()) {
        size_t nl = s.find("\r\n", pos);
        if (nl == std::string::npos) {
            if (pos < s.size()) lines.push_back(s.substr(pos));
            break;
        }
        lines.push_back(s.substr(pos, nl - pos));
        pos = nl + 2;
    }
    return lines;
}

static std::string to_lower(std::string s) {
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// ----------------------------------------------------------------------------
//  handle_connect — HTTPS через метод CONNECT
//  Браузер прислал "CONNECT host:port". Подключаемся к серверу, отвечаем 200
//  и дальше просто гоняем байты туннелем, не заглядывая внутрь TLS
// ----------------------------------------------------------------------------
static void handle_connect(int client, const std::string& target) {
    std::string host = target;
    int port = 443;
    if (size_t colon = target.rfind(':'); colon != std::string::npos) {
        host = target.substr(0, colon);
        port = std::stoi(target.substr(colon + 1));
    }

    bool bypass = should_bypass_vpn(host);
    log_line("[https host] " + host);
    log_line(std::string("[route] ") + (bypass ? "BYPASS_VPN_VIA_WIFI" : "DEFAULT_VPN"));

    int upstream = open_socket(host, std::to_string(port), bypass);

    const char* ok =
        "HTTP/1.1 200 Connection Established\r\n"
        "Connection: close\r\n"
        "\r\n";
    send_all(client, ok, std::strlen(ok));

    relay(client, upstream);
    close(upstream);
}

// ----------------------------------------------------------------------------
//  handle_http — обычный HTTP proxy-запрос
//  Absolute-form URL из первой строки ("GET http://host/path") переписываем в
//  origin-form ("GET /path"), выкидываем keep-alive, дочитываем тело, шлём
// ----------------------------------------------------------------------------
static void handle_http(int client, const std::string& data) {
    // Делим на заголовок и (возможно, неполное) тело по пустой строке
    size_t sep = data.find("\r\n\r\n");
    std::string header = (sep == std::string::npos) ? data : data.substr(0, sep);
    std::string body   = (sep == std::string::npos) ? ""   : data.substr(sep + 4);

    std::vector<std::string> lines = split_lines(header);
    if (lines.empty())
        return;

    // Первая строка: METHOD target VERSION
    std::string first = lines[0];
    size_t sp1 = first.find(' ');
    size_t sp2 = first.rfind(' ');
    if (sp1 == std::string::npos || sp2 <= sp1)
        return;
    std::string method  = first.substr(0, sp1);
    std::string target  = first.substr(sp1 + 1, sp2 - sp1 - 1);
    std::string version = first.substr(sp2 + 1);

    // Разбираем "http://host:port/path?query"
    std::string rest = target;
    if (rest.starts_with("http://"))
        rest = rest.substr(7);
    std::string path = "/";
    if (size_t slash = rest.find('/'); slash != std::string::npos) {
        path = rest.substr(slash); // всё от первого "/" — это путь + query
        rest = rest.substr(0, slash);
    }
    std::string host = rest;
    int port = 80;
    if (size_t colon = rest.rfind(':'); colon != std::string::npos) {
        host = rest.substr(0, colon);
        port = std::stoi(rest.substr(colon + 1));
    }

    bool bypass = should_bypass_vpn(host);
    log_line("[http host] " + host);
    log_line(std::string("[route] ") + (bypass ? "BYPASS_VPN_VIA_WIFI" : "DEFAULT_VPN"));

    // Новая первая строка — в origin-form
    std::string new_first = method + " " + path + " " + version;

    // Пересобираем заголовки: выкидываем Connection/Proxy-Connection и в конце
    // принудительно ставим Connection: close
    std::string headers = new_first + "\r\n";
    size_t content_length = 0;
    for (size_t i = 1; i < lines.size(); ++i) {
        std::string low = to_lower(lines[i]);
        if (low.starts_with("connection:") || low.starts_with("proxy-connection:"))
            continue; // выкинули keep-alive
        if (low.starts_with("content-length:"))
            content_length = std::stoul(lines[i].substr(lines[i].find(':') + 1));
        headers += lines[i] + "\r\n";
    }
    headers += "Connection: close\r\n";

    // Тело могло прийти не целиком (мы прочитали лишь первый recv в handle_client)
    // Дочитываем у клиента, пока не наберём весь Content-Length
    while (body.size() < content_length) {
        char buf[65536];
        ssize_t r = recv(client, buf, sizeof(buf), 0);
        if (r <= 0)
            break;
        body.append(buf, static_cast<size_t>(r));
    }

    std::string new_data = headers + "\r\n" + body;

    int upstream = open_socket(host, std::to_string(port), bypass);
    send_all(upstream, new_data.data(), new_data.size());

    // Читаем ответ сервера до закрытия и переливаем клиенту
    char buf[65536];
    ssize_t r;
    while ((r = recv(upstream, buf, sizeof(buf), 0)) > 0) {
        if (!send_all(client, buf, static_cast<size_t>(r)))
            break;
    }
    close(upstream);
}

// ----------------------------------------------------------------------------
//  handle_client — одно входящее соединение от браузера
//  CONNECT → HTTPS-туннель, всё остальное → обычный HTTP
// ----------------------------------------------------------------------------
static void handle_client(int client) {
    try {
        char buf[65536];
        ssize_t r = recv(client, buf, sizeof(buf), 0);  // первый кусок запроса
        if (r <= 0) {
            close(client);
            return;
        }
        std::string data(buf, static_cast<size_t>(r));

        // Разбираем первую строку: "METHOD target VERSION"
        size_t eol = data.find("\r\n");
        std::string first = data.substr(0, eol);
        size_t sp1 = first.find(' ');
        size_t sp2 = first.find(' ', sp1 == std::string::npos ? 0 : sp1 + 1);
        if (sp1 == std::string::npos || sp2 == std::string::npos) {
            close(client);
            return;
        }
        std::string method = first.substr(0, sp1);
        std::string target = first.substr(sp1 + 1, sp2 - sp1 - 1);

        if (to_lower(method) == "connect")
            handle_connect(client, target);
        else
            handle_http(client, data);
    } catch (const std::exception& e) {
        log_line(std::string("[error] ") + e.what());
        const char* resp =
            "HTTP/1.1 502 Bad Gateway\r\n"
            "Content-Type: text/plain\r\n"
            "Connection: close\r\n"
            "\r\n"
            "Proxy error\n";
        send_all(client, resp, std::strlen(resp));
    }
    close(client);
}

// ----------------------------------------------------------------------------
//  main — поднимаем слушающий сокет и на каждое соединение — отдельный поток
// ----------------------------------------------------------------------------
int main() {
    // ВАЖНО для C++: если писать в сокет, который собеседник уже закрыл, ОС
    // шлёт сигнал SIGPIPE, и по умолчанию он УБИВАЕТ весь процесс. Python это
    // сам превращает в исключение, а в C++ надо сделать вручную.
    signal(SIGPIPE, SIG_IGN);

    int server = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(LISTEN_PORT); // порядок байтов сети
    inet_pton(AF_INET, LISTEN_HOST, &addr.sin_addr); // "127.0.0.1" → байты

    if (bind(server, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        std::perror("bind");
        return 1;
    }
    listen(server, 100);

    log_line(std::string("Proxy listening on ") + LISTEN_HOST + ":" +
             std::to_string(LISTEN_PORT));
    log_line("Press Ctrl+C to stop");

    while (true) {
        int client = accept(server, nullptr, nullptr); // ждём подключение
        if (client < 0)
            continue;
        // Отдаём соединение отдельному потоку и «отвязываем» его (detach):
        // поток живёт сам по себе, а мы сразу ждём следующего клиента
        std::thread(handle_client, client).detach();
    }
}