package main

import (
	"bufio"    // буферизованное чтение из сокета
	"fmt"      // сборка строк/ошибок (аналог printf)
	"io"       // io.Copy, io.Reader — потоки байтов
	"log"      // потокобезопасный вывод в лог
	"net"      // сокеты, слушатель, дозвон
	"net/http" // разбор HTTP-запроса за нас
	"os"       // getenv, stdout
	"os/exec"  // запуск внешних команд (networksetup)
	"strings"  // работа со строками
	"syscall"  // низкоуровневые системные вызовы (setsockopt)
	"time"     // таймауты
)

const (
	listenAddr = "127.0.0.1:18080"

	// Опции ядра macOS «привязать сокет к интерфейсу». В stdlib Go их нет,
	// поэтому берём числами из <netinet/in.h>: IPv4 → 25, IPv6 → 125
	ipBoundIF   = 0x19
	ipv6BoundIF = 0x7d

	dialTimeout = 15 * time.Second // дозвон до сервера
	idleTimeout = 60 * time.Second // тишина в туннеле → закрываем
	bufSize     = 64 * 1024
)

// Wi-Fi-интерфейс для обхода VPN. Имя и индекс вычисляем один раз при старте
var (
	wifiName  string
	wifiIndex int
)

// detectWifiInterface определяет Wi-Fi-интерфейс:
//  1. переменная окружения BYPASS_IFACE;
//  2. вывод networksetup -listallhardwareports;
//  3. запасной вариант en0.
func detectWifiInterface() string {
	if env := os.Getenv("BYPASS_IFACE"); env != "" {
		return env
	}
	out, err := exec.Command("networksetup", "-listallhardwareports").Output()
	if err != nil {
		return "en0"
	}
	// Вывод разбит на блоки пустой строкой; ищем блок Wi-Fi и строку "Device:"
	// range идёт по срезу строк (Split вернул []string). `_` значит «это
	// значение мне не нужно» (здесь не нужен индекс, только сам блок).
	for _, block := range strings.Split(string(out), "\n\n") {
		if !strings.Contains(block, "Hardware Port: Wi-Fi") &&
			!strings.Contains(block, "Hardware Port: AirPort") {
			continue
		}
		for _, line := range strings.Split(block, "\n") {
			// CutPrefix возвращает (остаток, было_ли_совпадение). Если ok=true,
			// строка начиналась с "Device:", а dev — это то, что после него.
			if dev, ok := strings.CutPrefix(strings.TrimSpace(line), "Device:"); ok {
				return strings.TrimSpace(dev)
			}
		}
	}
	return "en0"
}

// shouldBypassVPN — оканчивается ли домен на .ru или .рф (punycode .xn--p1ai)
func shouldBypassVPN(host string) bool {
	host = strings.ToLower(host)
	// HasSuffix — «заканчивается ли строка на …».
	return strings.HasSuffix(host, ".ru") || strings.HasSuffix(host, ".xn--p1ai")
}

// dial открывает TCP-соединение к host:port и возвращает два значения:
// соединение (net.Conn — это интерфейс, «любой сокет») и ошибку.

// Резолв имени, перебор IPv4/IPv6 и «Happy Eyeballs» (гонка семейств с форой
// 300 мс) net.Dialer делает сам — в C++/Python это писали руками (неблокирующий
// connect + select). При bypass=true сокет привязывается к Wi-Fi через Control-хук.
func dial(host, port string, bypass bool) (net.Conn, error) {
	// net.Dialer{...} — литерал структуры: создаём объект и сразу заполняем поля.
	d := net.Dialer{Timeout: dialTimeout}
	// В Go функции — это тоже значения. Кладём функцию bindToWifi в поле Control
	// Dialer вызовет её для каждого сокета перед подключением.
	if bypass {
		d.Control = bindToWifi
	}
	return d.Dial("tcp", net.JoinHostPort(host, port))
}

// bindToWifi ставит IP_BOUND_IF / IPV6_BOUND_IF на индекс Wi-Fi-интерфейса для
// каждого сокета до connect. Сигнатура задана тем, что ждёт Dialer.Control;
// `_ string` — второй параметр нам не нужен, поэтому имя `_`
func bindToWifi(network, _ string, c syscall.RawConn) error {
	if wifiIndex == 0 {
		// fmt.Errorf собирает ошибку-значение. %q подставит строку в кавычках.
		return fmt.Errorf("wi-fi interface %q not found", wifiName)
	}
	level, opt := syscall.IPPROTO_IP, ipBoundIF
	if strings.HasSuffix(network, "6") { // "tcp6"
		level, opt = syscall.IPPROTO_IPV6, ipv6BoundIF
	}
	var setErr error
	// c.Control даёт «сырой» дескриптор сокета (fd) в момент, когда его уже
	// создали, но ещё не подключили. Внутри анонимной функции (замыкания) ставим
	// опцию. Замыкание видит внешние переменные — поэтому пишем в setErr
	if err := c.Control(func(fd uintptr) {
		setErr = syscall.SetsockoptInt(int(fd), level, opt, wifiIndex)
	}); err != nil {
		return err
	}
	return setErr
}

// handleConn обрабатывает одно входящее соединение от браузера
// CONNECT → HTTPS-туннель, всё остальное → обычный HTTP
func handleConn(client net.Conn) {
	// defer откладывает вызов до выхода из функции — что бы дальше ни случилось,
	// соединение закроется. Это как finally в других языках
	defer client.Close()

	br := bufio.NewReader(client)
	// http.ReadRequest сам разбирает строку запроса и заголовки
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	// Сравниваем метод с константой из пакета (http.MethodConnect == "CONNECT").
	if req.Method == http.MethodConnect {
		handleConnect(client, br, req)
	} else {
		handleHTTP(client, req)
	}
}

// HTTPS: браузер прислал "CONNECT host:port". Дозваниваемся, отвечаем 200 и
// дальше просто гоняем байты, не заглядывая внутрь TLS.
func handleConnect(client net.Conn, br *bufio.Reader, req *http.Request) {
	host, port := splitHostPort(req.Host, "443")
	bypass := shouldBypassVPN(host)
	logRoute("https", host, bypass)

	upstream, err := dial(host, port, bypass)
	if err != nil {
		writeError(client, err)
		return
	}
	defer upstream.Close()

	// io.WriteString возвращает (число, ошибка)
	if _, err := io.WriteString(client,
		"HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n"); err != nil {
		return
	}
	tunnel(client, br, upstream)
}

// handleHTTP — обычный HTTP proxy-запрос: разбираем, переписываем в origin-form,
// keep-alive выключаем, ответ сервера переливаем клиенту
func handleHTTP(client net.Conn, req *http.Request) {
	host := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		port = "80"
	}
	bypass := shouldBypassVPN(host)
	logRoute("http", host, bypass)

	upstream, err := dial(host, port, bypass)
	if err != nil {
		writeError(client, err)
		return
	}
	defer upstream.Close()

	// req.Write отправляет запрос в origin-form (path вместо абсолютного URL),
	// сам подставляет Host, Content-Length и переливает тело из br
	req.Close = true                   // попросить сервер закрыть соединение после ответа
	req.Header.Del("Proxy-Connection") // убрать заголовок, адресованный прокси
	if err := req.Write(upstream); err != nil {
		return
	}
	// перелить ответ сервера обратно клиенту
	io.Copy(client, upstream) // Connection: close гарантирует, что чтение завершится
}

// tunnel гоняет байты в обе стороны, пока одна из сторон не закроется или пока
// не наступит 60 с тишины. Две горутины вместо ручного select из Python/C++
func tunnel(client net.Conn, clientR io.Reader, upstream net.Conn) {
	// Канал — «труба» для сигналов между горутинами. Буфер на 2, чтобы обе
	// горутины смогли записать в него, даже если мы читаем медленно
	done := make(chan struct{}, 2)

	// `go f(...)` запускает f в отдельной лёгкой «горутине» — параллельно,
	// поэтому обе стороны копируются одновременно
	go pipe(upstream, client, clientR, done)  // клиент → сервер (через буфер br)
	go pipe(client, upstream, upstream, done) // сервер → клиент
	<-done
	client.Close()
	upstream.Close()
	<-done // дождаться вторую горутину, чтобы она не утекла
}

// pipe копирует из src в dst, сбрасывая дедлайн простоя на каждом чтении.
// srcConn — то же соединение, что и src (нужно для SetReadDeadline; когда src
// это bufio.Reader, дедлайн ставим на его базовый conn)
func pipe(dst, srcConn net.Conn, src io.Reader, done chan<- struct{}) {
	// defer с анонимной функцией: при выходе положить сигнал в канал.
	// struct{}{} — «пустышка», значение без данных (важен сам факт сигнала).
	defer func() { done <- struct{}{} }()

	// make([]byte, N) — создать срез (динамический массив) из N байт.
	buf := make([]byte, bufSize)
	for { // for без условия = бесконечный цикл (while true)
		srcConn.SetReadDeadline(time.Now().Add(idleTimeout))
		n, err := src.Read(buf) // n — сколько байт реально прочитали
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil { // buf[:n] — первые n байт
				return
			}
		}
		if err != nil { // сюда попадём и при закрытии стороны, и при таймауте
			return
		}
	}
}

// splitHostPort разбивает "host:port"; при отсутствии порта возвращает defPort
func splitHostPort(hostport, defPort string) (string, string) {
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		return h, p
	}
	return hostport, defPort
}

func logRoute(scheme, host string, bypass bool) {
	route := "DEFAULT_VPN"
	if bypass {
		route = "BYPASS_VPN_VIA_WIFI"
	}
	log.Printf("[%s host] %s", scheme, host)
	log.Printf("[route] %s", route)
}

func writeError(client net.Conn, err error) {
	log.Printf("[error] %v", err) // %v — «значение в удобочитаемом виде»
	io.WriteString(client,
		"HTTP/1.1 502 Bad Gateway\r\n"+
			"Content-Type: text/plain\r\n"+
			"Connection: close\r\n\r\n"+
			"Proxy error\n")
}

func main() {
	log.SetOutput(os.Stdout) // писать лог в stdout (скрипт перенаправит его в файл)
	log.SetFlags(0)          // без временных меток — как в остальных версиях

	wifiName = detectWifiInterface()
	// InterfaceByName возвращает (*Interface, error). Если ошибки нет — берём .Index
	if iface, err := net.InterfaceByName(wifiName); err == nil {
		wifiIndex = iface.Index
	} else {
		log.Printf("[warn] интерфейс %q не найден: %v", wifiName, err)
	}

	// net.Listen открывает слушающий сокет. Возвращает (Listener, error)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err) // Fatalf печатает сообщение и завершает программу
	}
	log.Printf("Proxy listening on %s (bypass iface: %s)", listenAddr, wifiName)
	log.Printf("Press Ctrl+C to stop")

	for {
		conn, err := ln.Accept() // ждать нового клиента (блокирует до подключения)
		if err != nil {
			continue
		}
		go handleConn(conn) // по горутине на соединение
	}
}
