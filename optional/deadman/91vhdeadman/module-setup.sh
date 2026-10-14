#!/bin/bash
# void-hardened: initramfs выключает машину, если её перезагрузил vh-deadman через MOR
# (optional/deadman, docs/13). К этому моменту прошивка уже стёрла RAM.
check() { return 0; }
depends() { return 0; }
install() {
	inst_hook cmdline 01 "$moddir/vh-deadman-flag.sh"
}
