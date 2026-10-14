# 04. Графика: iGPU и GTX 1650

> Модуль 4 промпта. Настройка: `VH_GPU` в `vh.conf`. Файлы:
> `/etc/udev/rules.d/99-vh-dgpu-off.rules`, `module_blacklist` в cmdline.

## 1. Почему не проприетарный драйвер NVIDIA

Пакет `nvidia` в Void собирает модуль ядра через `nvidia-dkms` **на этой машине**
(нужны dkms, gcc и заголовки ядра), а такой модуль подписан не ключом сборки ядра —
`lockdown`/`module.sig_enforce` его не загрузит. Пришлось бы отказаться от lockdown и
поставить компилятор — то есть ослабить сразу две меры. CUDA и NVENC — цена этого
решения.

## 2. Два варианта

| | **A: `VH_GPU=igpu`** (по умолчанию) | **B: `VH_GPU=nouveau`** |
|---|---|---|
| Что работает | mango, браузер и видео — на Intel UHD | то же + dGPU через nouveau (GL) и NVK (Vulkan), `DRI_PRIME=1 программа` |
| dGPU | обесточена (D3cold), драйвера нет, `nouveau` в blacklist | спит, пока не нужна (runtime PM nouveau) |
| Внешний монитор на HDMI dGPU | **не работает** | работает |
| Поверхность атаки | нет драйвера dGPU в ядре | драйвер nouveau доступен через render node |
| Пакеты | — | + `linux-firmware-nvidia`, `mesa-vulkan-nouveau` |
| Батарея и нагрев | лучше всего | почти как A, пока dGPU не используется |

Рекомендация: **A**, если внешний монитор не нужен или подключён к порту iGPU
(проба покажет, [00](00-prepare.md)); иначе **B**.

## 3. Как обесточивается dGPU без драйвера (вариант A)

Без драйвера dGPU остаётся в состоянии D0 (включена) и тратит ~5–8 Вт — тепло, которое
отнимает турбо у CPU. Ядро умеет «усыплять» устройство без драйвера: само устройство
остаётся в D0, но **корневой порт PCIe** над ним переходит в D3cold (питание снято),
если разрешён runtime PM у устройства и у всех его функций. Правило udev:

```
# видеофункция и 3D-контроллер NVIDIA: разрешить runtime PM
ACTION=="add", SUBSYSTEM=="pci", ATTR{vendor}=="0x10de", ATTR{class}=="0x030000", ATTR{power/control}="auto"
# HDMI-аудио функцию dGPU держит snd_hda_intel — удаляем её с шины
ACTION=="add", SUBSYSTEM=="pci", ATTR{vendor}=="0x10de", ATTR{class}=="0x040300", ATTR{remove}="1"
```

Проверка:

```sh
lspci -nn | grep -i 10de                                   # адрес dGPU, например 01:00.0
cat /sys/bus/pci/devices/0000:01:00.0/power/runtime_status # suspended
cat /sys/bus/pci/devices/0000:00:01.0/power/runtime_status # корневой порт: suspended
```

Если `active` — что-то держит устройство: `lspci -k -s 01:00.1` (аудио не удалено?),
или прошивка не умеет D3cold (тогда помогает только вариант B с runtime PM nouveau).

## 4. Вариант B: nouveau и NVK

- Turing (TU117) поддерживается nouveau; полная работа (частоты, Vulkan) — через
  прошивку GSP из `linux-firmware-nvidia` [ПРОВЕРИТЬ: `dmesg | grep -i gsp`;
  на ядрах, где GSP не включён по умолчанию для Turing, — `nouveau.config=NvGspRm=1`
  в `VH_EXTRA_CMDLINE`].
- Запуск программы на dGPU: `DRI_PRIME=1 программа`. mango работает на iGPU.
- Render node dGPU (`/dev/dri/renderD129`) — того же правила `render 0660`, что и iGPU.
  Песочница браузера получает **только** render node i915 — dGPU ей не видна.

## 5. iGPU: что получают программы

- mango получает `/dev/dri/card0` (режимы экрана, KMS) через **seatd** — пользователю не
  нужна группа `video`, и посторонний процесс не может открыть card0.
- Render node `/dev/dri/renderD128` (рендеринг без доступа к экрану): в Void по
  умолчанию `0666` — драйвер i915 доступен любому процессу. Правило
  `99-vh-devices.rules` сужает до группы `render` (пользователь и браузер).
- **VA-API** (аппаратное декодирование, драйвер `iHD` из `intel-media-driver`): H.264,
  HEVC, VP9 — да, AV1 — нет. В доверенном профиле браузера AV1 выключен
  (`media.av1.enabled=false`) → YouTube отдаёт VP9, который декодирует GPU: в разы
  меньше нагрузка на CPU и расход батареи.

Проверка от админа: `xbps-install libva-utils && vainfo` — строки `VAProfileVP9…` и
`VAProfileH264…` с `VAEntrypointVLD` (после проверки пакет можно удалить: он тянет X11).

## Итог главы

| Защищает от | Остаточный риск | Цена в скорости | Цена в удобстве |
|---|---|---|---|
| DKMS и неподписанных модулей; драйвера dGPU в ядре (A); посторонних процессов на render node | Поверхность драйвера i915 для доверенного профиля браузера | Нет CUDA/NVENC; игры — только через nouveau/NVK (B) | A: внешний монитор на HDMI dGPU не работает |
