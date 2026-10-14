# 08. Рабочий стол и изоляция приложений

> Модуль 8 промпта. Файлы: `/usr/local/bin/{vh-session,vh-wlfilter,vh-browse}`,
> `/usr/local/sbin/vh-browser`, `/usr/local/libexec/vh/browser-sandbox`,
> `/etc/vh/{mango-vh.conf,firefox/*}`, `/etc/pipewire/pipewire-pulse.conf.d/60-vh-sandbox.conf`,
> `/etc/wireplumber/wireplumber.conf.d/60-vh-sandbox.conf`, `/etc/apparmor.d/vh.*`.

## 1. Как запускается сеанс

```
agetty tty1 → login (PAM: пароль, pam_access, faillock, /run/user/UID)
 → bash -l → /etc/profile.d/zz-vh.sh: umask 077, PYTHONNOUSERSITE, LESSSECURE
 → exec /usr/local/bin/vh-session
     → mango  (экран и ввод — через seatd)
         exec-once: pipewire (+ wireplumber, pipewire-pulse), vh-wlfilter, netline, zbg, swayidle
     ← mango завершился (выход или падение)
     → kill -KILL -1   (ни один процесс пользователя не переживает сеанс)
 → снова приглашение входа, а не шелл
```

**seatd** вместо elogind: маленький root-демон, который выдаёт активному сеансу
дескрипторы `/dev/dri/card0` и устройств ввода и отбирает их при переключении на
другой VT. Пользователю не нужны группы `video` и `input` — достаточно `_seatd`.

**`kill -KILL -1` в конце сеанса.** Вредонос, отвязавшийся от сеанса (`setsid`, `nohup`,
двойной fork), переживает обычный выход. Здесь — нет: после mango убиваются все
процессы этого UID. Процессы браузера (другой UID) завершаются через гибель их
родителя-doas: `bwrap --die-with-parent` убивает всю песочницу ([5](#5-браузер-в-песочнице)).

Тайм-ауты: блокировка через 5 минут простоя (`swayidle` → `swaylock`), «защищённая
комбинация» — `Super+L`.

## 2. mango и что в нём важно для защиты

**mango** (mangowc 0.17 из репозитория Void) — композитор на wlroots. Его конфиг
пользователя `~/.config/mango/config.conf` подключает два файла:

```
source=/etc/mango/config.conf      # штатный конфиг пакета
source=/etc/vh/mango-vh.conf       # настройки void-hardened (root)
```

Ключевое из `/etc/vh/mango-vh.conf`:

| Строка | Зачем |
|---|---|
| `focus_on_activate=0` | окно не забирает фокус само — нельзя «украсть» ввод пароля новым окном |
| `allow_shortcuts_inhibit=0` | приложение не может отключить привязки mango — «защищённая комбинация» работает всегда |
| `windowrule=isopensilent:1,tags:9,appid:^vh-sandbox` | окна браузера открываются на теге 9 без фокуса |
| `exec-once=vh-wlfilter` | фильтр Wayland для песочниц (раздел 3) |

**IPC mango** — UNIX-сокет `$XDG_RUNTIME_DIR/mango-<pid>.sock`. Он принимает
`dispatch spawn,…`, то есть любой процесс пользователя может через него запускать
команды, менять привязки, выходить из сеанса. Это как IPC sway в промпте. Браузер и
просмотрщики его не видят (другой UID и отдельный `XDG_RUNTIME_DIR` в песочнице).
Закрыть его от процессов *самого* пользователя — дочерний профиль AppArmor сеанса
(`optional/session-apparmor`, [13](13-optional.md)).

## 3. Модель безопасности Wayland и vh-wlfilter

В X11 любое окно читает чужой экран и нажатия. В Wayland по умолчанию — нет, но
композиторы на wlroots дают **любому клиенту** «привилегированные» протоколы:

| Протокол | Что даёт атакующему |
|---|---|
| `zwlr_screencopy`, `ext_image_copy_capture`, `zwlr_export_dmabuf` | снимки экрана — пароли, документы |
| `zwlr_data_control`, `ext_data_control` | чтение буфера обмена в любой момент |
| `zwp_virtual_keyboard`, `zwlr_virtual_pointer` | ввод команд в ваш терминал |
| `zwp_input_method_v2` | перехват ввода в полях других окон |
| `zwlr_layer_shell` | поддельный экран блокировки или запрос пароля поверх всего |
| `ext_session_lock` | захват блокировки экрана |
| `zwlr_foreign_toplevel`, `zwlr_gamma_control`, `zwlr_output_*` | список окон, управление экраном |
| `zwp_keyboard_shortcuts_inhibit` | отключить привязки композитора |

sway решает это протоколом **security-context-v1**: песочница получает отдельный
сокет, на котором привилегированные протоколы скрыты. **В mango 0.17 его нет**
(проверено по исходникам: в `main.c` все эти глобалы создаются для всех клиентов, фильтра
нет). Поэтому песочницы подключаются к mango через **vh-wlfilter** — прокси на
python3 (только стандартная библиотека):

```
Firefox ──/run/vh-sandbox/wayland──► vh-wlfilter ──$XDG_RUNTIME_DIR/wayland-0──► mango
          (сокет 0660, группа browser)  (процесс пользователя)
```

Что делает прокси:
1. **Белый список глобалов.** Клиент видит только перечисленные в `ALLOWED` объекты:
   compositor, shm, seat, output, xdg-shell, dmabuf, viewporter, fractional-scale,
   cursor-shape, буфер обмена `wl_data_device`, text-input… Всё прочее он просто не
   видит. Это **строже** security-context, где скрывается чёрный список: новый
   привилегированный протокол в будущей версии mango автоматически закрыт.
2. **Попытка угадать номер скрытого глобала** (`wl_registry.bind` с чужим номером)
   рвёт соединение.
3. **Пометка окон.** Каждое окно песочницы получает `app_id` «vh-sandbox.…» и заголовок
   «[песочница] …». Клиент не может это подделать: прокси переписывает его запросы.
   Правила mango опираются на этот app_id.
4. **Запросы полноэкранного режима отбрасываются.** Страница не нарисует во весь экран
   «экран блокировки» с полем пароля. Видео во весь экран — `Super+F` (решение
   принимает mango, а не страница).

Цена: сообщения Wayland браузера идут через процесс python — десятки микросекунд на
сообщение. Буферы кадров передаются дескрипторами (dmabuf/shm), их содержимое
через прокси не копируется. [Замер](11-performance.md).

**Что прокси не закрывает.** Буфер обмена отдаётся окну, получившему фокус, — это
основа копирования и вставки. Правило: пароли копируйте с автоочисткой
(`wl-copy --paste-once`). Полноэкранное окно можно имитировать большим обычным
окном без рамок — поэтому «защищённая комбинация»: перед вводом пароля в любой
экран блокировки нажмите `Super+L`, настоящий swaylock ляжет поверх.

Проверка: из песочницы `wayland-info` (пакет `wayland-utils`) не должен показать ни
одного протокола из таблицы выше.

## 4. Звук песочницы

PipeWire поднимает дополнительный сокет PulseAudio для песочницы
(`/run/vh-sandbox/pulse`, `client.access = "restricted"`). Права «restricted»-клиентам
выдаёт WirePlumber: по умолчанию `rx` **на всё, включая микрофон** — видно и можно
подключить к своему потоку. Наш менеджер прав `vh-sandbox`
(`wireplumber.conf.d/60-vh-sandbox.conf`) делает источники звука и видео
(`Audio/Source`, `Video/Source` и т. п.) для таких клиентов невидимыми: воспроизведение
работает, запись — нет.

Проверка в песочнице: `pactl list short sources` пусто, `pactl list short sinks` — ваши выходы.

## 5. Браузер в песочнице

```
Super+B → vh-browse → doas /usr/local/sbin/vh-browser trusted      (правило без пароля, только этот аргумент)
  → [root] проверка DOAS_USER, наличие /run/vh-sandbox/wayland
  → exec nsenter --net=/proc/1/ns/net      (сеть init: если сеанс в пустом netns — optional/session-netns)
  → exec setpriv --reuid=browser --regid=browser --init-groups --reset-env
             --no-new-privs --inh-caps=-all --bounding-set=-all
  → exec browser-sandbox trusted                                      [uid browser]
  → exec bwrap …                                                      [новые namespace]
  → firefox
```

Каждая ступень — `exec`: родителем bwrap остаётся процесс doas, и когда сеанс
пользователя убивает свои процессы (`kill -KILL -1`), doas гибнет, а с ним
(`--die-with-parent`) — вся песочница.

### Почему отдельный пользователь

Разные UID — граница ядра: браузер не читает файлы пользователя (`/home/user` —
0700), не шлёт сигналы его процессам, не трогает их память. bwrap и AppArmor —
второй и третий слой поверх этой границы.

### bwrap: что видит Firefox

| | Внутри песочницы |
|---|---|
| `/usr` | только чтение |
| `/usr/lib/firefox` | собран заново: файлы пакета + наш `vh.cfg` и `vh-autoconfig.js`, только чтение |
| `/etc` | только fonts, ssl, resolv.conf, hosts, nsswitch.conf, localtime, ld.so.cache, политика Firefox; `passwd`/`group` — одна строка (имена других пользователей не видны) |
| `/proc` | свой (новый pid namespace), `/proc/interrupts`, `/proc/softirqs`, `/proc/stat` — пустые |
| `/dev` | минимальный; GPU — только render node i915 (доверенный профиль) |
| `/tmp`, `/dev/shm` | каталоги на хостовом tmpfs с `noexec` (этот флаг в user namespace снять нельзя) |
| `HOME` | `/var/lib/vh-browser/trusted` (постоянный, noexec) или пустой tmpfs (одноразовый) |
| `~/Downloads` | `/home/xfer` — общий с пользователем каталог |
| Wayland | только `/run/vh-sandbox/wayland` (vh-wlfilter) |
| звук | только `/run/vh-sandbox/pulse` |
| сеть | общая (`--share-net`), но nftables: 80/443 и QUIC, без LAN и localhost |
| D-Bus, IPC mango, основной сокет Wayland и PipeWire | нет |

Ключевые флаги: `--unshare-all --share-net` (свои pid, ipc, uts, cgroup, user namespace),
`--disable-userns --assert-userns-disabled` (внутри песочницы новые user namespace
создать нельзя — весь класс эксплойтов ядра «из своего userns»: nf_tables, overlayfs,
FUSE — закрыт), `--cap-drop ALL`, `--clearenv`, `--new-session` (нет TIOCSTI в чужой
терминал), `--die-with-parent`.

> Firefox умеет работать без user namespace: его собственная песочница контента
> (seccomp-bpf + брокер файлов) работает, теряется только его chroot/pid/net-слой —
> его заменяет bwrap. Проверка: `about:support` → «Песочница».
> Chromium без userns и без setuid-помощника не запускается — поэтому Firefox.

**Счётчики прерываний** (`/proc/interrupts`, `/proc/stat`) замаскированы: по ним код в
песочнице может восстановить тайминги нажатий клавиш — в том числе при вводе
пароля в swaylock.

### Два профиля

| | `vh-browse` (доверенный, `Super+B`) | `vh-browse untrusted` (`Super+Shift+B`) |
|---|---|---|
| Профиль | постоянный: логины, закладки, история | пустой при каждом запуске, исчезает после выхода |
| JIT | включён | **выключен** (`javascript.options.*`) — JS в разы медленнее, но исчезает главный класс RCE |
| GPU | render node i915: WebRender, VA-API | нет: программная отрисовка, WebGL и WebGPU выключены |
| Fullscreen API | работает внутри окна (прокси не даёт развернуть на экран) | выключен |
| Для чего | свои сайты: почта, банк, работа | всё остальное: ссылки, поиск, незнакомые сайты |

### Политики и autoconfig

Политики Firefox (`/etc/vh/firefox/policies-{trusted,untrusted}.json`) подставляются в
песочницу как `/etc/firefox/policies/policies.json` — на **установку**, а не на профиль:
скомпрометированный браузер не изменит их через `prefs.js`. Заблокированы:

- телеметрия, Studies, обновления самого Firefox (обновляет xbps);
- DoH (DNS только через unbound), включён HTTPS-only;
- **плагины GMP** (OpenH264 от Cisco, Widevine) и EME — закрытые бинарники, которые
  Firefox скачивает сам мимо репозитория. H.264 декодируется системным ffmpeg
  (`libavcodec6`) и VA-API;
- WebRTC; камера, микрофон, геолокация, уведомления — запрос сразу отклоняется;
- расширения: все запрещены, кроме uBlock Origin (ставится автоматически);
- `network.IDN_show_punycode` (домены-двойники видны как xn--…), автозаполнение
  паролей в формах выключено.

Политика `Preferences` разрешает не все настройки: `javascript.options.*` и
`app.normandy.*` запереть ею нельзя (проверено по документации политик). Их запирает
**autoconfig** (`vh-trusted.cfg`/`vh-untrusted.cfg`, `lockPref`): файлы
подмонтированы в каталог Firefox внутри песочницы, пакет их не перезаписывает.

## 6. Каталог обмена /home/xfer

Браузер скачивает в `~/Downloads` (внутри песочницы) = `/home/xfer`; у пользователя
`~/Downloads` — ссылка туда же. Права: владелец `browser`, группа `xfer` (оба
пользователя), `2770` (setgid — новые файлы получают группу xfer), ACL по умолчанию
`u:user:rwX, u:browser:rwX` — иначе файл, скачанный с umask 077, был бы нечитаем.

Монтирование `noexec,nosymfollow`: скачанное не запускается, а **симлинки, подложенные
браузером, не разыменовываются вообще** — ни редактором, ни архиватором
(`fs.protected_symlinks` в этом каталоге не действует: он не sticky-world-writable).

Не открывайте скачанное программами вне песочницы, если не доверяете файлу:
просмотрщики в песочнице — `optional/viewers` ([13](13-optional.md)).

## 7. netline

Панель (`netline`, `zrun`, `zwifi`, `zbt`, `zwall`, `zbg`, `zpower`, `zcal`) — ваш проект на
Zig. Сборка — в RAM live-среды при установке (`install/build-netline.sh`):

- в репозитории Void есть только zig 0.13, а netline нужен 0.16 — компилятор
  скачивается с ziglang.org и проверяется подписью **minisign** и SHA-256;
- в установленную систему попадают только готовые бинарники (`/usr/local/bin`, root,
  0755) и их хэши в `/etc/vh/netline.sha256`. Компилятора в системе нет;
- [ВНЕ ОГРАНИЧЕНИЙ]: бинарники не из репозитория Void. Цена отказа — без панели.
  Смягчение: сборка из исходников в проверенной live-среде, хэши для сверки.

Под void-hardened (с изменениями netline для систем без NetworkManager и logind):

| Меню | Через что работает |
|---|---|
| zwifi | iwd по D-Bus (группа `netdev`); пароль — своему агенту iwd, затирается сразу. 802.1X — профиль от админа `/var/lib/iwd/<SSID>.8021x` |
| zbt | BlueZ; при `VH_BLUETOOTH=optional` переключатель сам запускает сервис (`doas vh-bluetooth on`) |
| zpower | без logind: `doas /usr/bin/reboot` / `poweroff` по правилам без пароля; сна нет |
| статус панели | sysfs и netlink — без демонов |

Собственная защита netline: seccomp без exec/fork/socket, Landlock, брокер команд,
собранный при компиляции (см. README netline).

**Обновить netline** (новый коммит): с live-флешки или на другой машине собрать и
положить бинарники, либо разрешить разработку на этой машине — `VH_DEV_DIR` и Zig в
`~/dev` (тогда компилятор в системе есть — осознанная цена).

## 8. AppArmor

**AppArmor** — LSM с профилями: для процесса под профилем ядро проверяет каждое
обращение к файлу, сети, capability, сигналу по правилам профиля — **даже у root и
даже внутри своего user namespace**. Профили загружаются в стадии 1
(`09-apparmor.sh` из `runit-void-apparmor`) до старта сервисов.

Профили базового слоя (`/etc/apparmor.d/vh.*`):

- **`vh.firefox`** — Firefox внутри песочницы. Запрещены: сетевые семейства, кроме
  inet и unix (в том числе `alg` — модули AF_ALG, загруженные для iwd, иначе доступны
  всем; `packet`), монтирование, capability `net_admin`, `net_raw`, `sys_module`,
  `sys_admin`, исполнение и mmap-исполнение из `/tmp`, `/dev/shm`, HOME и Downloads.
  `flags=(attach_disconnected)`: внутри bwrap пути вне корня песочницы «отсоединены».
- **`vh.unbound`, `vh.chronyd`, `vh.dhcpcd`, `vh.iwd`** — сервисы: только свои файлы,
  только нужные сетевые семейства и capability. `alg` разрешён только iwd.

```sh
doas aa-status                      # загруженные профили и процессы под ними
doas svlogtail kernel | grep apparmor   # отказы: operation, profile, name
```

Режим «complain» (только журнал, без запрета) для отладки профиля:
`doas aa-complain /etc/apparmor.d/vh.firefox`, обратно — `aa-enforce`.

## 9. Если сеанс не стартует

1. Войдите на tty2 админом: `doas cat /run/user/$(id -u user)/mango.log` — ошибки mango.
2. `sv status seatd` — seatd работает? Пользователь в группе `_seatd`? (`id user`)
3. `ls -l /dev/dri/` — card0 и renderD128 есть?
4. Чёрный экран после входа — mango упал, `vh-session` убил процессы и вернул login:
   смотрите mango.log.

## Итог главы

| Защищает от | Остаточный риск | Цена в скорости | Цена в удобстве |
|---|---|---|---|
| Снимков экрана, чтения буфера, ввода в терминал, поддельных экранов из браузера; эксплойтов ядра из userns; доступа браузера к файлам пользователя, LAN, микрофону; закрепления через профиль и prefs; закрытых плагинов | Буфер обмена отдаётся окну в фокусе; большое окно без рамок вместо полноэкранного; поверхность i915 у доверенного профиля; IPC mango для процессов самого пользователя | прокси Wayland: мкс на сообщение; одноразовый профиль без JIT и GPU — в разы медленнее JS | Окна браузера на теге 9 без автофокуса; полноэкранный режим — Super+F; файлы для сайтов — через ~/Downloads |
