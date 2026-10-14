# 06. Сеть: защита (L2–L7)

> Модуль 6 промпта. Файлы: `/etc/nftables.conf`, `/etc/iwd/main.conf`,
> `/etc/unbound/unbound.conf`, `/etc/chrony.conf`, `/etc/dhcpcd.conf`, `/etc/resolv.conf`,
> `/etc/sysctl.d/40-vh-network.conf`. Скорость сети — [07](07-network-speed.md): там те же
> файлы, в каждой строке помечено, к чему она относится.

## 1. Общая картина

```
приложения пользователя ──┐
браузер (uid browser) ────┤ DNS: только 127.0.0.1:53
admin ────────────────────┘          │
                              unbound (uid _unbound) ── DoT 853 ──> Quad9 / Mullvad (TLS, проверка имени)
                              chrony  (uid chrony)   ── NTS 4460/123 ──> NTS-серверы
                              iwd (Wi-Fi, WPA3, DHCP) / dhcpcd (Ethernet)
                                        │
                              nftables: что угодно кроме разрешённого — drop
```

Принципы: **один** резолвер, к которому ходят все; наружу DNS уходит только
зашифрованным; время — только аутентифицированное; входящих соединений нет вовсе;
правила файрвола — из одного файла, загружаются до сети.

## 2. nftables

### Основы

**netfilter** — подсистема ядра, пропускающая каждый пакет через **хуки** (точки):
`prerouting` (пришёл), `input` (адресован нам), `forward` (транзит), `output` (наш
исходящий), `postrouting`. **nftables** — язык правил для неё. **Цепочка** привязана к
хуку с приоритетом (меньше — раньше), правила в ней проверяются по порядку, политика
(`policy drop`) — что делать, если ни одно правило не сработало.

**conntrack** (отслеживание соединений) работает в `prerouting` с приоритетом −200. Он
помечает каждый пакет: `new`, `established` (ответ на наше соединение), `related`
(например, ICMP-ошибка про наше соединение), `invalid`. Поэтому правило
`ct state established,related accept` первым — это «пропускать ответы», а
разрешения пишутся только для новых соединений.

**skuid** — UID владельца сокета для **исходящих** пакетов. Это и есть «каждой
программе — своя сеть»: unbound ходит на 853, chrony — на 4460/123, браузер — на
80/443, остальные — по правилам.

### Набор правил (`/etc/nftables.conf`, разбор)

```
table inet vh {                                   # inet = IPv4 и IPv6 одной таблицей
  set dot_servers { ... }                          # IP DoT-апстримов из unbound.conf
  set private4 { flags interval; ... }             # частные и служебные сети
  set browser_lan { type ipv4_addr . inet_service; flags timeout; }   # исключения LAN для браузера
  set browser_lo_ports { type inet_service; flags timeout; }          # localhost-порты для браузера

  chain raw_pre { type filter hook prerouting priority raw; ... }     # −300: до conntrack
  chain input   { type filter hook input  priority filter; policy drop; ... }
  chain forward { ...; policy drop; }
  chain output  { type filter hook output priority filter; policy drop; ... }
}
```

**raw_pre** — ранние отбрасывания до conntrack (дёшево): чужой `127.0.0.0/8` не с `lo`,
источники `0/8`, `224/4`, `240/4` («марсиане»), невозможные комбинации TCP-флагов.
**RFC1918, 100.64/10 и 169.254/16 — не марсиане**: в чужой сети это адрес DHCP-сервера
и шлюза, их отбрасывание сломало бы подключение. `ct state invalid` проверяется
только после conntrack — в raw состояния ещё нет.

**input**: `lo` — да; ICMP redirect — отбросить **до** правила ct (conntrack помечает
redirect, относящийся к нашему соединению, как related — без этого правила
поддельный redirect перенаправил бы наш трафик); ответы — да; DHCP-ответы — да;
остальное — журнал (с лимитом) и drop. Входящих сервисов нет.

**output** по порядку:
1. ответы и `lo` (своя цепочка);
2. DHCP;
3. `_unbound` → только `@dot_servers:853/tcp`; **все остальные** на 53 и 853 (UDP и TCP)
   — drop: ни одна программа не спросит DNS мимо unbound (и не отправит данные
   DNS-туннелем на свой сервер);
4. `chrony` → 4460/tcp (NTS-KE) и 123/udp;
5. `browser` → LAN только по `@browser_lan`, остальные частные сети — drop; 80/443 TCP и
   443 UDP (QUIC) — да;
6. `include "/etc/vh/nft/people.nft"` — root и люди. В базовом слое: `root` → только
   443/tcp (xbps по HTTPS); `user`, `admin` — сеть есть (git, ssh, ping). Строгий режим
   «у людей сети нет, root — только к зеркалам и на время» подменяет этот файл
   (`optional/strict-net`, [13](13-optional.md));
7. всё прочее — журнал и drop.

**out_lo**: к `127.0.0.1:53` — по `include "/etc/vh/nft/lo-dns.nft"` (в базовом слое —
всем; в строгом — браузеру, chrony и временным разрешениям), остальным — drop;
браузеру к остальным портам localhost — только `@browser_lo_ports`
(скомпрометированный браузер не постучится в локальные сервисы других
пользователей); остальным — можно.

> `include` внутри цепочки — обычная возможность nft: файл подставляется на месте при
> загрузке набора. Набор по-прежнему загружается целиком одной командой, атомарно.

### Временные разрешения

Правила не меняются в работе — меняются только элементы set'ов с `timeout` (ядро
само удаляет их по истечении):

```sh
doas nft add element inet vh browser_lan '{ 192.168.1.1 . 443 timeout 30m }'   # админка роутера на 30 минут
doas nft add element inet vh browser_lo_ports '{ 8000 timeout 2h }'             # свой dev-сервер
doas nft list set inet vh browser_lan
```

Постоянное исключение — добавить `elements = { … }` в set в `/etc/nftables.conf` и
`doas nft -f /etc/nftables.conf`.

### Если правила не загрузились

`06-vh-nftables.sh` при ошибке загружает аварийную таблицу `vh_failsafe` «запретить
всё, кроме lo», а сервисы iwd/dhcpcd проверяют наличие таблицы и без неё не
стартуют (**fail-closed**). Проверка синтаксиса перед применением: `nft -c -f /etc/nftables.conf`.

## 3. Wi-Fi: iwd

**iwd** (Intel) — демон Wi-Fi вместо wpa_supplicant + dhcpcd + NetworkManager: один
процесс, свой DHCP, криптография через ядро (AF_ALG). Управление — `iwctl` или
D-Bus (так работает меню Wi-Fi в netline). Права на D-Bus у групп `wheel` и `netdev`.

```sh
iwctl station wlan0 scan
iwctl station wlan0 get-networks
iwctl station wlan0 connect "ИмяСети"        # спросит пароль
iwctl known-networks list
```

`/etc/iwd/main.conf` — защита:

| Параметр | Значение | Зачем |
|---|---|---|
| `AddressRandomization` | `network` | на каждую сеть — свой постоянный случайный MAC: сеть узнаёт вас при повторном подключении (стабильный DHCP), но сети между собой вас не связывают |
| `AddressRandomizationRange` | `full` | все 6 байт случайны (с `nic` остаётся OUI Intel — признак производителя) |
| `ManagementFrameProtection` | `1` | PMF (защита кадров управления: нельзя «выбить» вас поддельным deauth), если точка умеет. `2` — только PMF: ломает подключение к старым сетям |
| `NameResolvingService` | `none` | DNS из DHCP игнорируется — резолвер только unbound |
| `EnableIPv6` | `false` | IPv6 выключен в ядре |
| `[DriverQuirks] DefaultInterface` | `iwlwifi` | не пересоздавать интерфейс при старте: быстрее и не теряются настройки `wlan0` |
| `SendHostname` (в профилях) | по умолчанию false | имя машины не уходит в чужой DHCP |

### WPA3 и evil twin

**WPA2-PSK:** перехватив рукопожатие (сообщение M2 с MIC), атакующий перебирает пароль
офлайн. Поддельная точка с тем же именем, объявившая WPA2, получает M2 даже от
клиента, который обычно ходит по WPA3 («откат»).
**WPA3-SAE:** обмен по протоколу Dragonfly — перебор возможен только онлайн, по
попытке на подключение.

Для своих сетей включите в профиле запрет отката
(`/var/lib/iwd/ИмяСети.psk`):

```ini
[Settings]
TransitionDisable=true
DisabledTransitionModes=personal
```

Тогда iwd не подключится к «своей» сети через WPA2. Своя точка доступа: **только**
WPA3-SAE с H2E (не смешанный WPA2/WPA3), PMF обязателен, WPS выключен.

**SSID confusion** (CVE-2023-52424): если у двух сетей одинаковый пароль, клиента
можно подключить к другой из них. У каждой своей сети (в том числе 2,4 и 5 ГГц одной
точки) — **свой** пароль.

### Wi-Fi при работающем кабеле

По умолчанию Wi-Fi остаётся подключённым и при кабеле (режим «скорость»:
переключение кабель → Wi-Fi мгновенное, маршрут Ethernet приоритетнее по метрике).
Цена: стек 802.11 и iwd разбирают кадры чужих точек, пока работает кабель. Режим
«безопасность» — блокировать Wi-Fi при кабеле: `doas rfkill block wlan` вручную или
`optional/strict-net`.

## 4. DNS: unbound

### Зачем свой резолвер

- **DNSSEC** — ответы подписаны владельцами зон: подменённый ответ (публичный Wi-Fi,
  отравление кэша) не пройдёт проверку подписи.
- **DoT** (DNS over TLS, порт 853) — запросы к апстриму зашифрованы: сеть не видит и
  не подменяет, какие имена вы спрашиваете.
- **Кэш** — повторные запросы мгновенно ([07](07-network-speed.md)).

### Разбор `/etc/unbound/unbound.conf`

- `interface: 127.0.0.1`, `access-control` — только локальные клиенты.
- `username: "_unbound"`, `chroot: "/etc/unbound"` — после старта работает без прав
  root и видит только свой каталог.
- `auto-trust-anchor-file: "/etc/unbound/var/root.key"` — корневой ключ DNSSEC из пакета
  `dnssec-anchors`, обновляется по RFC 5011 через сам DNS. Ключ — в подкаталоге `var/`,
  куда unbound может писать; сам `/etc/unbound` с конфигом остаётся за root.
  `unbound-anchor` не используется: ему нужен HTTPS, а unbound разрешён только 853.
- `forward-tls-upstream: yes`, `forward-addr: 9.9.9.9@853#dns.quad9.net` — DoT по
  IP-адресу (нет «курицы и яйца» с DNS для DNS), после `#` — имя, которое должно быть
  в сертификате. Проверка имени работает только при заданном `tls-cert-bundle` —
  у нас `/etc/unbound/ca-bundle.pem` (копия системных корневых сертификатов внутри chroot).
- `harden-*`, `val-clean-additional`, `deny-any`, `minimal-responses` — отбрасывать
  лишнее и подозрительное в ответах.
- `private-address: 10.0.0.0/8 …` — **защита от DNS rebinding**: если имя из интернета
  резолвится в адрес вашей LAN или 127.0.0.1, адрес вырезается. Иначе страница
  `evil.example` после смены записи DNS обращалась бы к вашему роутеру «от своего
  имени».
- `local-zone: "use-application-dns.net." always_nxdomain` — сигнал Firefox не включать
  DoH самому (он и так выключен политикой).

Апстримы по умолчанию — Quad9 (два адреса) и Mullvad: у них **разные** удостоверяющие
центры, и смена УЦ у одного не оставит систему без DNS. Пиннинг сертификатов (файл
только с нужными УЦ вместо всего системного хранилища) — `optional/dns-pin`.

### Проверка

```sh
getent hosts voidlinux.org                         # отвечает
doas svlogtail | grep unbound                      # ошибки TLS/DNSSEC
# DNSSEC: заведомо сломанная подпись должна давать отказ
getent hosts dnssec-failed.org || echo "правильно: SERVFAIL"
# неверное имя в forward-addr ломает резолв (fail-closed): поменять #dns.quad9.net
# на #wrong.example, doas sv restart unbound, getent hosts … → отказ; вернуть.
```

`resolv.conf` — одна строка `nameserver 127.0.0.1`. Его никто не переписывает: iwd с
`NameResolvingService=none`, dhcpcd с `nohook resolv.conf`, openresolv не установлен.

## 5. Время: chrony с NTS

От точного времени зависят TLS (срок действия сертификатов), DNSSEC (срок подписей),
журналы. Обычный NTP не аутентифицирован: подделав время, можно заставить принять
просроченный (отозванный) сертификат или старую подпись DNSSEC.

**NTS** (Network Time Security): по TLS (порт 4460) клиент получает ключи, дальше NTP-пакеты
(123/udp) аутентифицированы. `/etc/chrony.conf`:

```
server time.cloudflare.com iburst nts       # и ещё три NTS-сервера
minsources 2                                # нужно согласие двух источников
authselectmode require                      # неаутентифицированные — не использовать
ntsdumpdir /var/lib/chrony                  # ключи NTS между перезапусками
makestep 1.0 3                              # быстрый старт: шаг часов в первых обновлениях
maxchange 100 1 -1                          # после синхронизации скачки >100 с игнорировать
rtcsync                                     # синхронизировать аппаратные часы
port 0 / cmdport 0                          # не сервер; chronyc — только через unix-сокет
```

Проверка: `doas chronyc -N authdata` (столбец Mode: NTS), `chronyc tracking`.

> При полностью неверных часах (севшая батарейка RTC) TLS к NTS не пройдёт. Тогда
> один раз: `doas date -s 'YYYY-MM-DD HH:MM'` и `doas sv restart chronyd`.

## 6. Ethernet: dhcpcd

`VH_ETH=dhcp`: сервис `dhcpcd-eth0` только для `eth0`, только IPv4. Из DHCP не берётся
ничего, кроме адреса и маршрута: `nohook resolv.conf, ntp.conf, hostname`,
`nooption domain_name_servers, ntp_servers, host_name`; своё имя не отправляется.
dhcpcd сам разделён на процессы с разными правами (privilege separation, пользователь
`_dhcpcd`). `VH_ETH=static` — адрес и шлюз задаются сервисом `vh-eth-static`.

## 7. Bluetooth (VH_BLUETOOTH)

Bluetooth — большой стек в ядре плюс демон `bluetoothd` (BlueZ), доступный по радио
любому рядом (классы атак BlueBorne, BleedingTooth). Режимы:

- `off` — модули `bluetooth`, `btusb` и др. запрещены; адаптер не работает вовсе.
- **`optional` (по умолчанию)** — bluez установлен, но `bluetoothd` не запущен и радио
  заблокировано (`rfkill`). Включить на время (наушники) — `vh-bluetooth on` через
  правило doas без пароля (клавиша или меню netline), выключить — `vh-bluetooth off`.
- `on` — bluetoothd работает всегда.

## 8. Диагностика

```sh
ip -br a                          # адреса
ip route                          # маршруты (метрики: eth 100, wlan 300+)
iwctl station wlan0 show          # состояние Wi-Fi
doas nft list ruleset             # правила (сверить с /etc/nftables.conf)
doas svlogtail kernel | grep vh-  # что отбросил файрвол (vh-in-drop / vh-out-drop)
ss -tulpn                         # слушает только unbound на 127.0.0.1:53
ping -c3 9.9.9.9                  # ICMP-сокет (группа netdiag)
getent hosts example.org          # DNS через unbound
```

«Сайт не открывается в браузере, а `curl` от пользователя работает» — смотрите
`vh-out-drop` с `uid` браузера: скорее всего это адрес из частной сети
(`browser_lan`) или нестандартный порт.

## Итог главы

| Защищает от | Остаточный риск | Цена в скорости | Цена в удобстве |
|---|---|---|---|
| Подмены DNS и времени, слежки за DNS-запросами, отката WPA3→WPA2, deauth, трекинга по MAC, DNS-туннелей, DNS rebinding, входящих соединений, доступа браузера к LAN и localhost | Доверие к DoT/NTS-провайдерам и системным УЦ (без пиннинга); стек 802.11 разбирает чужие кадры; DoH-клиенты в программах пользователя | TLS к апстриму: десятки мс на холодный запрос (кэш и prefetch это скрывают) | Админка роутера из браузера — через `browser_lan`; captive portal — [12](12-daily.md) |
