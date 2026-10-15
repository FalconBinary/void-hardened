/* vh-usb-udev — решение об авторизации USB (optional/usb-auth, docs/13). Вызывается udev.
 *
 * Ядро загружено с usbcore.authorized_default=2: устройства на внутренних портах
 * (connect_type=hardwired по ACPI) авторизуются сами, внешние — нет. У корневых хабов
 * interface_authorized_default=0: даже у авторизованного устройства интерфейсы
 * создаются неавторизованными, драйвер к ним не привязывается. Этот помощник решает:
 *
 *   интерфейс внутреннего устройства  → авторизовать (кроме камеры при VH_CAMERA=no и
 *                                        Bluetooth при VH_BLUETOOTH=off);
 *   свой FIDO2-ключ из /etc/vh/usb-keys.conf (точный порт, VID:PID, serial,
 *   один интерфейс HID)              → авторизовать устройство и его интерфейс;
 *   устройство, подключённое «vh-usb attach» → только интерфейсы класса 08 (накопитель);
 *   всё прочее                        → остаётся неавторизованным (BadUSB-клавиатура мертва).
 *
 * Дескрипторы устройства пишет само устройство — разбор с проверкой каждой длины.
 *
 *   vh-usb-udev device|interface DEVPATH
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "vh.h"

#define KEYS "/etc/vh/usb-keys.conf"
#define ENV "/etc/vh/vh.env"
#define ATTACH_DIR "/run/vh/usb-attach"

static void klog(const char *fmt, ...) VH_PRINTF(1, 2);
static void klog(const char *fmt, ...)
{
	char m[512], line[600];
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(m, sizeof(m), fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	n = snprintf(line, sizeof(line), "<5>vh-usb: %s\n", m);
	if (n < 0 || (size_t)n >= sizeof(line))
		n = (int)sizeof(line) - 1;
	int fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return;
	if (write(fd, line, (size_t)n) < 0) {
	}
	close(fd);
}

static const char *attr(const char *dev, const char *name, char *out, size_t sz)
{
	char p[PATH_MAX];
	snprintf(p, sizeof(p), "%s/%s", dev, name);
	return rd(p, out, sz);
}

static void wr(const char *dev, const char *name, const char *val)
{
	char p[PATH_MAX];
	snprintf(p, sizeof(p), "%s/%s", dev, name);
	if (!write_str(p, val))
		klog("запись %s: %s", p, strerror(errno));
}

/* порт устройства «hardwired» по ACPI (встроенная камера, Bluetooth, клавиатура) */
static bool internal(const char *dev)
{
	char v[32];
	return strcmp(attr(dev, "port/connect_type", v, sizeof(v)), "hardwired") == 0;
}

/* интерфейсы из сырых дескрипторов (у неавторизованного устройства активной
 * конфигурации нет, но дескрипторы прочитаны): число и класс/протокол первого */
static size_t interfaces(const char *dev, int *cls0, int *proto0)
{
	char p[PATH_MAX];
	snprintf(p, sizeof(p), "%s/descriptors", dev);
	size_t len;
	unsigned char *raw = (unsigned char *)read_file(p, &len);
	if (!raw)
		return 0;
	size_t n = 0;
	for (size_t off = 0; off + 2 <= len;) {
		size_t ln = raw[off];
		if (ln < 2)
			break;
		if (raw[off + 1] == 4 && ln >= 9 && off + 9 <= len) {   /* INTERFACE */
			if (n == 0) {
				*cls0 = raw[off + 5];
				*proto0 = raw[off + 7];
			}
			n++;
		}
		off += ln;
	}
	free(raw);
	return n;
}

static bool key_match(const char *dev)
{
	const char *port = strrchr(dev, '/') + 1;
	char vid[16], pid[16], serial[256], vidpid[40];
	attr(dev, "idVendor", vid, sizeof(vid));
	attr(dev, "idProduct", pid, sizeof(pid));
	attr(dev, "serial", serial, sizeof(serial));
	snprintf(vidpid, sizeof(vidpid), "%s:%s", vid, pid);
	char *text = read_file(KEYS, NULL);
	if (!text)
		return false;
	bool ok = false;
	char *save = NULL;
	for (char *line = strtok_r(text, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		if (line[0] == '#')
			continue;
		char *s2 = NULL, *f0 = strtok_r(line, " \t", &s2), *f1 = strtok_r(NULL, " \t", &s2),
		     *f2 = strtok_r(NULL, " \t", &s2);
		if (!f0 || !f1 || !f2 || strcmp(f0, port) || strcmp(f1, vidpid) || strcmp(f2, serial))
			continue;
		/* FIDO: ровно один интерфейс, HID, без boot-протокола клавиатуры/мыши */
		int cls = -1, proto = -1;
		ok = interfaces(dev, &cls, &proto) == 1 && cls == 0x03 && proto == 0x00;
		break;
	}
	free(text);
	return ok;
}

static void on_device(const char *dev)
{
	char v[256], vid[16], pid[16], man[128], prod[128];
	const char *port = strrchr(dev, '/') + 1;
	if (strcmp(attr(dev, "authorized", v, sizeof(v)), "1") == 0)
		return;
	if (key_match(dev)) {
		klog("свой FIDO-ключ на %s — авторизую", port);
		wr(dev, "authorized", "1");
		return;
	}
	klog("заблокировано: %s %s:%s «%s %s» — флешка: vh-usb attach", port,
	     attr(dev, "idVendor", vid, sizeof(vid)), attr(dev, "idProduct", pid, sizeof(pid)),
	     attr(dev, "manufacturer", man, sizeof(man)), attr(dev, "product", prod, sizeof(prod)));
	mkdirs("/run/vh", 0755);
	int fd = open("/run/vh/usb-blocked", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0644);
	if (fd >= 0) {
		if (write(fd, port, strlen(port)) < 0) {
		}
		close(fd);
	}
}

static void on_interface(const char *intf)
{
	char dev[PATH_MAX], v[64];
	snprintf(dev, sizeof(dev), "%s", intf);
	*strrchr(dev, '/') = 0;
	const char *c = attr(intf, "bInterfaceClass", v, sizeof(v));
	char *end;
	long cls = strtol(*c ? c : "ff", &end, 16);
	if (*end || cls < 0 || cls > 0xFF)
		cls = 0xFF;
	if (strcmp(attr(intf, "authorized", v, sizeof(v)), "1") == 0)
		return;
	char att[PATH_MAX];
	snprintf(att, sizeof(att), ATTACH_DIR "/%s", strrchr(dev, '/') + 1);
	if (path_exists(att)) {
		if (cls == 0x08)
			wr(intf, "authorized", "1");
		return;
	}
	if (key_match(dev) && cls == 0x03) {
		wr(intf, "authorized", "1");
		return;
	}
	if (internal(dev)) {
		struct kvs e = {0};
		kv_read(&e, ENV, 0);
		if (cls == 0x0E && strcmp(kv_get(&e, "VH_CAMERA", ""), "yes") != 0)
			return;               /* камера: только профиль звонков */
		if (cls == 0xE0 && strcmp(kv_get(&e, "VH_BLUETOOTH", ""), "off") == 0)
			return;
		wr(intf, "authorized", "1");
	}
}

int main(int argc, char **argv)
{
	vh_prog = "vh-usb-udev";
	if (argc != 3)
		return 2;
	char *p = xasprintf("/sys%s", argv[2]), real[PATH_MAX];
	if (!realpath(p, real) || !startswith(real, "/sys/devices/") || !strchr(real + 13, '/'))
		return 2;
	if (strcmp(argv[1], "device") == 0)
		on_device(real);
	else
		on_interface(real);
	return 0;
}
