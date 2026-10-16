/* Константы device-mapper из заголовков ядра — сверка с zig/tools/vh-deadman.zig. */
#include <stdio.h>
#include <sys/ioctl.h>
#include <linux/dm-ioctl.h>

int main(void)
{
	printf("%zu %#lx %#lx %u\n", sizeof(struct dm_ioctl), (unsigned long)DM_DEV_SUSPEND,
	       (unsigned long)DM_TARGET_MSG, DM_SUSPEND_FLAG | DM_SKIP_LOCKFS_FLAG | DM_NOFLUSH_FLAG);
	return 0;
}
