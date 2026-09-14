# tunnel-lab

Экспериментальный IP-туннель: Go-клиент для macOS (utun), Go-сервер для Linux (TUN), один активный клиент. Выбор транспорта в JSON: `sip`, `webrtc`, `reality`.

```
macOS IP → utun → клиент → выбранный транспорт → сервер → TUN → Linux forwarding/NAT → default gateway
```

## Транспорты

* **SIP:** настоящий синтаксис SIP/2.0, `OPTIONS` для взаимной аутентификации и `MESSAGE` для самих данных. Постоянное двустороннее TCP-соединение, опционально TLS (`sip.tls`). Тело `application/octet-stream`: AES-256-GCM с отдельными ключами направлений, ключи сессии выведены из PSK и двух случайных challenge. Аутентификация — собственное расширение `X-Tunnel-*`, не SIP Digest. SIP-прокси/регистратор не требуется и не поддерживается. UDP-транспорт SIP не реализован. Одна ожидающая MESSAGE-транзакция на направление ограничивает скорость на больших RTT; это измеримый экспериментальный транспорт.
* **WebRTC:** Pion v4, обмен SDP через HTTPS `/offer`, реальные ICE/STUN connectivity checks, DTLS и SRTP. Данные в RTP-медиатреке; DataChannel не используется. `vp8` согласует PT 96, `h264` — PT 102. Данные в payload — фрагменты нашего протокола, **не декодируемые видеокадры**. Наличие соответствующего payload type не доказывает неотличимость от видеозвонка. Для доступных локальных адресов внешний STUN не нужен. STUN/TURN можно задать в конфиге.
* **REALITY:** встроенное ядро Xray, VLESS поверх REALITY. `target`, X25519-ключи, SNI, short ID и fingerprint настраиваются. На сервере VLESS соединения направляются только на внутренний TCP endpoint туннеля. Внешний процесс Xray не требуется. Для бинарных IP-пакетов не включён XTLS Vision flow.

MTU внутреннего интерфейса — 1280. В SRTP один пакет делится на фрагменты до 900 байт; сборка допускает перестановку и повторы, ограничена 64 незавершёнными пакетами и двумя секундами. При потерях пакет отбрасывается, повторной передачи на уровне туннеля нет. SIP/REALITY используют надёжный TCP-поток, что создаёт head-of-line blocking для вложенного TCP. Эти варианты стоит сравнивать измерениями.

## Сборка и тесты

Требуется Go 1.26; `go.mod` фиксирует toolchain 1.26.8. При необходимости Go загрузит его автоматически. Использование пакета WireGuard ограничено доступом к TUN, сам протокол WireGuard не используется.

```sh
go build -o bin/tunnel-lab ./cmd/tunnel-lab
go test ./... -count=1 -timeout=120s
go test -race ./... -count=1 -timeout=180s
```

Кросс-компиляция сервера:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/tunnel-lab-linux-amd64 ./cmd/tunnel-lab
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/tunnel-lab-linux-arm64 ./cmd/tunnel-lab
```

Интеграционные Go-тесты открывают локальные TCP/UDP-сокеты, проверяют двусторонние данные в SIP, SIP/TLS, WebRTC VP8/H.264 и REALITY. Для REALITY тест создаёт локальный TLS 1.3 target: доступ к внешним сайтам не нужен. Эти тесты не создают TUN и не меняют маршруты.

Проверка собранных CLI для SIP, SIP/TLS и обоих WebRTC-кодеков: `bash scripts/smoke.sh`. Скрипт требует `python3` для выбора свободных локальных портов.

## Быстрая проверка без TUN

Сгенерировать пару конфигов и сертификат. Каталог должен быть новым; существующие файлы команда не перезаписывает:

```sh
./bin/tunnel-lab init -out lab-webrtc -server 127.0.0.1:8443 -transport webrtc
```

В первом терминале:

```sh
./bin/tunnel-lab -config lab-webrtc/server.json -mode echo
```

Во втором:

```sh
./bin/tunnel-lab -config lab-webrtc/client.json -mode probe -count 100 -size 1280
```

`probe` проверяет точное совпадение случайных данных после каждого оборота и печатает средний RTT и полезную скорость. Это последовательная echo-проверка, **не тест максимальной пропускной способности**. `echo` и `probe` игнорируют сетевую автонастройку и не требуют root.

Аналогично для SIP:

```sh
./bin/tunnel-lab init -out lab-sip -server 127.0.0.1:5060 -transport sip
./bin/tunnel-lab init -out lab-sips -server 127.0.0.1:5061 -transport sip -sip-tls
```

И для REALITY (указать доступный серверу TLS 1.3 target и соответствующее имя):

```sh
./bin/tunnel-lab init -out lab-reality -server SERVER_IP:443 -transport reality \
  -target TARGET_HOST:443 -sni TARGET_HOST
```

Команда создаёт `server.json`, `client.json`, `cert.pem`, `server-key.pem` с правами 0600. Клиенту достаточно `client.json` и `cert.pem`; приватный ключ сервера остаётся на сервере. TLS-пути в JSON разрешаются относительно самого JSON. REALITY использует собственную проверку ключа и не требует этих PEM-файлов.

## Запуск macOS → Linux со всем исходящим IP-трафиком

1. Генерировать конфиги с реальным адресом Linux-сервера, например `-server 192.168.1.10:8443`. Для WebRTC адрес должен быть доступен по TCP и UDP. Если сервер за NAT, пробросить сигналинг TCP и диапазон UDP 40000–40100, задать внешний IP в `webrtc.nat_ips` или использовать TURN.
2. На Linux нужны `/dev/net/tun`, `ip`, `iptables`, `ip6tables`, `sysctl`, права root. Указать `network.egress`, если исходящий интерфейс нельзя однозначно выбрать из default route. Имя интерфейса серверного TUN по умолчанию `tlab0`.
3. На macOS проверить `network.dns_service` — это имя **сетевой службы** из `networksetup -listallnetworkservices`, например `Wi-Fi` или `Ethernet`. Генератор принимает `-dns-service Ethernet`. При пустом имени DNS не изменяется.
4. Сначала выполнить `echo`/`probe` между этими машинами. Затем запустить режим TUN:

Linux:

```sh
sudo ./tunnel-lab-linux-amd64 -config /path/to/server.json
```

macOS:

```sh
sudo ./bin/tunnel-lab -config /path/to/client.json
```

После `TUN ready` клиент имеет `10.77.0.2`, сервер `10.77.0.1`, IPv6 — `fd77::2` и `fd77::1`. Можно проверить `ping 10.77.0.1`, загрузку через `curl`, DNS и UDP. Сравнить исходящий IP на контролируемом внешнем endpoint с IP сервера.

Автонастройка клиента добавляет split default routes для IPv4 и IPv6. Существующие более специфичные маршруты (например локальная LAN) имеют приоритет. Адрес сервера, объявленные ICE-адреса, STUN/TURN и `network.bypass_ips` остаются через исходную сеть. DNS по умолчанию переключается на `1.1.1.1`, обращения к которому тоже идут через туннель. На сервере добавляются forwarding и MASQUERADE для IPv4/IPv6. Для выхода IPv6 серверу нужен работающий IPv6 upstream; без него IPv6-пакеты, направленные в туннель, не выйдут наружу.

Процесс восстанавливает свои маршруты, настройки DNS, forwarding и правила NAT при SIGINT/SIGTERM, ошибке настройки и завершении сессии. Клиент переподключается через 3 секунды; можно отключить `-reconnect=false`. **Kill switch не реализован:** после разрыва/остановки восстанавливается обычное прямое подключение. `kill -9`, перезагрузка или внешнее изменение настроек во время сессии не гарантируют автоматического отката. При аварийном завершении проверить маршруты, DNS и правила, перечисленные в журнале `network:`; запускать стенд в управляемой тестовой среде.

Если сеть настраивается вручную, установить `network.auto=false`. Программа создаст только интерфейс и напечатает его имя; адреса, маршруты, DNS и forwarding настраиваются отдельно. Автонастройка Linux-клиента не предусмотрена; Linux-клиент с ручными маршрутами используется в namespace-тесте.

## Основные поля конфига

```json
{
  "role": "client",
  "transport": "webrtc",
  "endpoint": "192.168.1.10:8443",
  "token": "GENERATE_A_SHARED_RANDOM_SECRET_OF_AT_LEAST_32_CHARACTERS",
  "tun": "utun",
  "tls": {"ca": "cert.pem", "server_name": "192.168.1.10"},
  "sip": {"tls": false},
  "webrtc": {
    "codec": "vp8",
    "ice_urls": [],
    "ice_username": "",
    "ice_credential": "",
    "udp_min": 0,
    "udp_max": 0,
    "nat_ips": []
  },
  "network": {
    "auto": true,
    "ipv4": "10.77.0.2/30",
    "peer4": "10.77.0.1",
    "ipv6": "fd77::2/126",
    "peer6": "fd77::1",
    "dns_service": "Wi-Fi",
    "dns": ["1.1.1.1"],
    "bypass_ips": []
  }
}
```

`listen` используется на сервере, `endpoint` — на клиенте. Неизвестные поля JSON отклоняются. Для смены транспорта изменить его на обеих сторонах и заполнить соответствующие параметры. Генерация отдельных пар конфигов снижает вероятность несовпадений.

## Полный изолированный Linux-стенд

```sh
sudo bash scripts/netns-test.sh ./bin/tunnel-lab-linux-amd64 sip
sudo bash scripts/netns-test.sh ./bin/tunnel-lab-linux-amd64 webrtc
sudo bash scripts/netns-test.sh ./bin/tunnel-lab-linux-amd64 reality
```

Скрипт создаёт три network namespace (клиент, сервер, внешний узел) и veth-соединения. Проверяет ICMPv4/v6, TCP-загрузку с хешем, UDP, DNS и видимый внешнему узлу адрес после NAT. Реальный default route хоста не меняется. Для REALITY нужен `openssl` с TLS 1.3; также требуются `python3`, `ip`, `iptables`, `ip6tables`, `ping`. После теста процессы и namespace удаляются, логи сохраняются в указанном скриптом временном каталоге. Для анализа пакетов можно отдельно запустить `tcpdump` в namespace.

Текущий уровень проверки и ограничения среды записаны в [VALIDATION.md](VALIDATION.md).

Протоколы: [SIP MESSAGE, RFC 3428](https://www.rfc-editor.org/rfc/rfc3428.html), [Pion](https://github.com/pion/webrtc), [REALITY](https://xtls.github.io/en/config/transports/reality.html).
