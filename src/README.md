# src — инструменты системы на C

Подробно — [docs/17-c-tools.md](../docs/17-c-tools.md): зачем C, замеры, флаги защиты, что
изменилось по сравнению с Python-версией.

```sh
sh src/build.sh КАТАЛОГ            # собрать (gcc, glibc-devel, openssl-devel, libxcrypt-devel)
install/build-tools.sh /mnt        # [LIVE] собрать в RAM live-среды и поставить в систему
sh tests/c/run.sh                  # проверка против Python-эталона (docker)
```

| Файл | Программа |
|---|---|
| `vh.c`, `vh.h` | общее: строки, файлы, конфиги `KEY=VALUE`, запуск программ без шелла |
| `hash.c`, `hash.h` | SHA-256 и BLAKE2b-512 |
| `seccomp.c`, `seccomp.h` | генератор фильтров seccomp-BPF (общий для `vh-seccomp` и `vh-open`) |
| `vh-wlfilter.c` | фильтрующий прокси Wayland для песочниц |
| `vh-seccomp.c` | фильтр для `bwrap --seccomp`, `--selftest` |
| `vh-acpid.c` | крышка, кнопка питания, простой |
| `vh-deadman.c` | стирание ключа LUKS (модуль deadman) |
| `vh-limine-update.c` | подпись UKI, `limine.conf` с хэшами, хэш конфига в Limine |
| `vh-pkg.c` | установка программ с обезвреживанием |
| `vh-uki-verify.c` | проверка входных данных UKI (модуль sb-offline-keys) |
| `vh-open.c` | просмотр файлов в песочнице (модуль viewers) |
| `vh-usb-udev.c` | решение об авторизации USB (модуль usb-auth) |
| `pin-fetch.c` | корень цепочки TLS для пиннинга (модуль dns-pin) |
| `vh-hashpw.c` | хэш пароля yescrypt — только VM-стенд |

Правила кода: только libc (и OpenSSL/libxcrypt там, где без них нельзя), никакого
шелла при запуске программ, каждое чтение недоверенных данных — после проверки длины,
сборка с `-Werror`.
