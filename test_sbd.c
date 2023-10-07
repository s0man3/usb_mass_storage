#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/blkdev.h>

static int __init sbd_init(void)
{
        return 0;
}

static void __exit sbd_exit(void)
{
}

module_init(sbd_init);
module_exit(sbd_exit);
