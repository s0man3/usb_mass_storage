#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/usb.h>
#include <linux/errno.h>

#define USB_VENDOR_ID 0x174c
#define USB_PRODUCT_ID 0x1153
#define MINOR_BASE 0x00

struct usb_simple_ahci {
        struct usb_device       *udev;
        struct usb_interface    *interface;
        struct usb_anchor       submitted;
        struct urb              *bulk_in_urb;
        unsigned char           *bulk_in_buffer;
        size_t                  bulk_in_size;
        size_t                  bulk_in_filled;
        size_t                  bulk_in_copied;
        __u8                    bulk_in_endpointAddr;
        __u8                    bulk_out_endpointAddr;
        int                     errors;
        bool                    ongoing_read;
        spinlock_t              err_lock;
        struct kref             kref;
        struct mutex            io_mutex;
        unsigned long           disconnected:1;
        wait_queue_head_t       bulk_in_wait;
};

static const struct usb_device_id simple_ahci_idtable[] = {
        { USB_DEVICE(USB_VENDOR_ID, USB_PRODUCT_ID) }
        {}
};
MODULE_DEVICE_TABLE(usb, simple_ahci_idtable);

#define to_usa_dev(d) container_of(d, struct usb_simple_ahci, kref)

static void simple_ahci_delete(struct kref *kref)
{
        struct usb_simple_ahci *dev = to_usa_dev(kref);
        usb_free_urb(dev->bulk_in_urb);
        usb_put_intf(dev->interface);
        usb_put_dev(dev->udev);
        kfree(dev->bulk_in_buffer);
        kfree(dev);
}

static ssize_t simple_ahci_read(struct file *file, char *buffer, size_t count,
                                loff_t *ppos)
{
}

static ssize_t simple_ahci_write(struct file *file, const char *user_buffer,
                                 size_t, loff_t *ppos)
{
}

static int simple_ahci_open(struct inode *inode, struct file *file)
{
        return 0;
}

static int simple_ahci_release(struct inode *inode, struct file *file)
{
        return 0;
}

static const struct file_operations simple_ahci_fops = {
        .owner =        THIS_MODULE,
        .read =         simple_ahci_read,
        .write =        simple_ahci_write,
        .open =         simple_ahci_open,
        .release =      simple_ahci_release,
};

struct usb_class_driver simple_ahci_class = {
        .name = "sahci",
        .fops = simple_ahci_fops,
        .minor_base = MINOR_BASE,
};

static int simple_ahci_probe(struct usb_interface *interface,
                             const struct usb_device_id *id)
{
        struct usb_simple_ahci *usa;

        dev = kzalloc(sizeof(*usa), GFP_KERNEL);
        kref_init(dev->kref);
        
        dev->udev = usb_get_dev(interface_to_usbdev(interface));
        dev->interface = usb_get_intf(interface);

        retval = usb_find_common_endpoints(interface->cur_altsetting,
                        &bulk_in, &bulk_out, NULL, NULL);
        if (retval) {
                dev_err(&interface->dev,
                        "Could not find both bulk-in and bulk-out endpoints\n");
                goto error;
        }

        dev->bulk_in_size = usb_endpoint_maxp(bulk_in);
        dev->bulk_in_endpointAddr = bulk_in->bEndpointAddress;
        dev->bulk_in_buffer = kmalloc(dev->bulk_in_size, GFP_KERNEL);
        if (!dev->bulk_in_buffer) {
                retval = -ENOMEM;
                goto error;
        }
        dev->bulk_in_urb = usb_alloc_urb(0, GFP_KERNEL);
        if (!dev->bulk_in_urb) {
                retval = -ENOMEM;
                goto error;
        }

        dev->bulk_out_endpointAddr = bulk_out->bEndpointAddress;

        usb_set_intfdata(interface, dev);

        retval = usb_register_dev(interface, &simple_ahci_class);
        if (retval) {
                dev_err(&interface->dev,
                        "Not able to get a minor for this device.\n");
                usb_set_intfdata(interface, NULL);
                goto error;
        }
        return 0;

error:
        kref_put(&dev->kref, simple_ahci_delete);
        return retval
}

static void simple_ahci_disconnect(struct usb_interfacer *interface)
{
}

static const usb_driver simple_ahci_driver = {
        .name = "simple_ahci_driver",
        .probe = simple_ahci_probe,
        .disconnect = simple_ahci_disconnect,
        .id_table = simple_ahci_idtable
};

module_usb_driver(simple_ahci_driver);
MODULE_AUTHOR("Soma Nakata");
MODULE_LICENSE("Dual BSD/GPL");
