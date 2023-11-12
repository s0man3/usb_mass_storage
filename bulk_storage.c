#include "bulk_storage.h"

static struct usb_driver bulk_storage_driver;
static void bulk_storage_draw_down(struct usb_bulk_storage *dev);

static const struct usb_device_id bulk_storage_idtable[] = {
        { USB_DEVICE(USB_VENDOR_ID, USB_PRODUCT_ID) },
        {},
};
MODULE_DEVICE_TABLE(usb, bulk_storage_idtable);

u8 lbaseek_h = 0;
u8 lbaseek_mh = 0;
u8 lbaseek_ml = 0;
u8 lbaseek_l = 0; 

char *write_buffer = NULL;

static void bulk_storage_delete(struct kref *kref)
{
        struct usb_bulk_storage *dev = to_usa_dev(kref);
        usb_free_urb(dev->bulk_in_urb);
        usb_put_intf(dev->interface);
        usb_put_dev(dev->udev);
        kfree(dev->bulk_in_buffer);
        kfree(dev);
}

static void bulk_storage_write_callback(struct urb *urb)
{
        struct usb_bulk_storage *dev;
        unsigned long flags;

        dev = urb->context;

        if (urb->status) {
                if(!(urb->status== -ENOENT ||
                   urb->status == -ECONNRESET ||
                   urb->status == -ESHUTDOWN))
                        dev_err(&dev->interface->dev,
                                "%s - nonzero write bulk status received: %d\n",
                                __func__, urb->status);
                spin_lock_irqsave(&dev->err_lock, flags);
                dev->errors = urb->status;
                spin_unlock_irqrestore(&dev->err_lock, flags);
        }

        usb_free_coherent(urb->dev, urb->transfer_buffer_length,
                        urb->transfer_buffer, urb->transfer_dma);
        up(&dev->limit_sem);
}

static void cmd_inquiry_cbwcb(u8 *buf)
{
        struct cbwcb_inquiry *pcbwcb;
        pcbwcb = (struct cbwcb_inquiry*)buf;
        pcbwcb->opecode = CMD_INQUIRY_OPCODE;
        pcbwcb->cmddt_evpd = CMD_INQUIRY_CE_ZERO;
        pcbwcb->page_code = CMD_INQUIRY_PC_ZERO;
        pcbwcb->allocation_length_h = CMD_INQUIRY_AL_H;
        pcbwcb->allocation_length_l = CMD_INQUIRY_AL_L;
        pcbwcb->control = CMD_INQUIRY_CONTROL;
}

static void cmd_read_cbwcb(char *buf)
{
        struct cbwcb_read *pcbwcb;
        pcbwcb = (struct cbwcb_read*)buf;
        pcbwcb->opecode = CMD_READ_OPCODE;
        pcbwcb->rdprotect = CMD_READ_RDPROTECT;
        pcbwcb->lba_h = lbaseek_h;
        pcbwcb->lba_mh = lbaseek_mh;
        pcbwcb->lba_ml = lbaseek_ml;
        pcbwcb->lba_l = lbaseek_l;
        pcbwcb->gnum = CMD_READ_GNUM;
        pcbwcb->txlength_h = CMD_READ_TXLENGTH_H;
        pcbwcb->txlength_l = CMD_READ_TXLENGTH_L;
        pcbwcb->control = CMD_READ_CONTROL;
}

static void cmd_write_cbwcb(char *buf)
{
        struct cbwcb_write *pcbwcb;
        pcbwcb = (struct cbwcb_write*)buf;
        pcbwcb->opecode = CMD_WRITE_OPCODE;
        pcbwcb->wrprotect = CMD_WRITE_WRPROTECT;
        pcbwcb->lba_h = lbaseek_h;
        pcbwcb->lba_mh = lbaseek_mh;
        pcbwcb->lba_ml = lbaseek_ml;
        pcbwcb->lba_l = lbaseek_l;
        pcbwcb->gnum = CMD_WRITE_GNUM;
        pcbwcb->txlength_h = CMD_WRITE_TXLENGTH_H;
        pcbwcb->txlength_l = CMD_WRITE_TXLENGTH_L;
        pcbwcb->control = CMD_WRITE_CONTROL;
}

static void cmd_inquiry_fill(char *buf)
{
        struct cbw *pcbw;
        pcbw = (struct cbw*)buf;
        
        pcbw->signature = CBW_SIGNATURE;
        pcbw->tag = CBW_CMD_INQUIRY_TAG;
        pcbw->txlength = CBW_CMD_INQUIRY_TXLENGTH;
        pcbw->flags = CBW_FLAG_IN;
        pcbw->lun = CBW_LUN;
        pcbw->cbwcb_length = CBW_CMD_INQUIRY_CMDLEN;
        cmd_inquiry_cbwcb(pcbw->cbwcb);
}

static void cmd_reset_fill(char *buf)
{
        struct reset *preset;
        preset = (struct reset*)buf;
        preset->request_type = CMD_RESET_TYPE;
        preset->request = CMD_RESET_REQUEST;
        preset->value = CMD_RESET_VALUE;
        preset->index = CMD_RESET_INDEX_IN;
        preset->length = CMD_RESET_LENGTH;
}

static void cmd_read_fill(char *buf)
{
        struct cbw *pcbw;
        pcbw = (struct cbw*)buf;
        
        pcbw->signature = CBW_SIGNATURE;
        pcbw->tag = CBW_CMD_READ_TAG;
        pcbw->txlength = CBW_CMD_READ_TXLENGTH;
        pcbw->flags = CBW_FLAG_IN;
        pcbw->lun = CBW_LUN;
        pcbw->cbwcb_length = CBW_CMD_READ_CMDLEN;
        cmd_read_cbwcb(pcbw->cbwcb);
}

static void cmd_write_fill(char *buf)
{
        struct cbw *pcbw;
        pcbw = (struct cbw*)buf;

        pcbw->signature = CBW_SIGNATURE;
        pcbw->tag = CBW_CMD_WRITE_TAG;
        pcbw->txlength = CBW_CMD_WRITE_TXLENGTH;
        pcbw->flags = CBW_FLAG_OUT;
        pcbw->lun = CBW_LUN;
        pcbw->cbwcb_length = CBW_CMD_READ_CMDLEN;
        cmd_write_cbwcb(pcbw->cbwcb);
}

static void cmd_snddata_fill(char *buf)
{
        memcpy(buf, write_buffer, WRITE_BYTE_SIZE);
}


static void cmd_fill_buf(char *buf, int cmd)
{
        switch(cmd) {
                case CMD_INQUIRY:
                        cmd_inquiry_fill(buf);
                        break;
                case CMD_RESET:
                        cmd_reset_fill(buf);
                        break;
                case CMD_READ:
                        cmd_read_fill(buf);
                        break;
                case CMD_WRITE:
                        cmd_write_fill(buf);
                        break;
                case CMD_SNDDATA:
                        cmd_snddata_fill(buf);
                        break;
        }
}

static size_t cmd_get_size(int cmd)
{
        switch(cmd) {
                case CMD_INQUIRY:
                        return CBW_SIZE;
                case CMD_RESET:
                        return CMD_SIZE_RESET;
                case CMD_READ:
                        return CBW_SIZE;
                case CMD_WRITE:
                        return CBW_SIZE;
                case CMD_SNDDATA:
                        return WRITE_BYTE_SIZE;
        }
        return -1;
}

static ssize_t bulk_out_snd(struct usb_bulk_storage *dev, struct file *file, int cmd)
{
        int retval = 0;
        struct urb *urb = NULL;
        char *buf = NULL;
        size_t writesize;

        writesize = cmd_get_size(cmd);
        if (!(file->f_flags & O_NONBLOCK)) {
                if (down_interruptible(&dev->limit_sem)) {
                        retval = -ERESTARTSYS;
                        goto exit;
                }
        } else {
                if (down_trylock(&dev->limit_sem)) {
                        retval = -EAGAIN;
                        goto exit;
                }
        }

        spin_lock_irq(&dev->err_lock);
        retval = dev->errors;
        if (retval < 0) {
                dev->errors = 0;
                retval = (retval == -EPIPE) ? retval : -EIO;
        }
        spin_unlock_irq(&dev->err_lock);
        if (retval < 0)
                goto error;

        urb = usb_alloc_urb(0, GFP_KERNEL);
        if (!urb) {
                retval = -ENOMEM;
                goto error;
        }

        mutex_lock(&dev->io_mutex);
        if (dev->disconnected) {
                mutex_unlock(&dev->io_mutex);
                retval = -ENODEV;
                goto error;
        }

        buf = usb_alloc_coherent(dev->udev, writesize, GFP_KERNEL,
                                 &urb->transfer_dma);
        if (!buf) {
                retval = -ENOMEM;
                goto error;
        }

        cmd_fill_buf(buf, cmd);

        usb_fill_bulk_urb(urb, dev->udev,
                          usb_sndbulkpipe(dev->udev, dev->bulk_out_endpointAddr),
                          buf, writesize, bulk_storage_write_callback, dev);
        urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;
        usb_anchor_urb(urb, &dev->submitted);

        retval = usb_submit_urb(urb, GFP_KERNEL);
        mutex_unlock(&dev->io_mutex);
        if (retval) {
                dev_err(&dev->interface->dev,
                        "%s - failed submitting write urb, error %d\n",
                        __func__, retval);
                goto error_unanchor;
        }

        usb_free_urb(urb);
        
        return writesize;

error_unanchor:
        usb_unanchor_urb(urb);
error:
        if (urb) {
                usb_free_coherent(dev->udev, writesize, buf, urb->transfer_dma);
                usb_free_urb(urb);
        }
        up(&dev->limit_sem);

exit:
        return retval;
}

static void bulk_storage_read_callback(struct urb *urb)
{
        struct usb_bulk_storage *dev;
        unsigned long flags;

        dev = urb->context;

        spin_lock_irqsave(&dev->err_lock, flags);
        if (urb->status) {
                if (!(urb->status == -ENOENT ||
                    urb->status == -ECONNRESET ||
                    urb->status == -ESHUTDOWN))
                        dev_err(&dev->interface->dev,
                                "%s - nonzero write bulk status received: %d\n",
                                __func__, urb->status);
                dev->errors = urb->status;
        } else {
                dev->bulk_in_filled = urb->actual_length;
        }
        dev->ongoing_read = 0;
        spin_unlock_irqrestore(&dev->err_lock, flags);
        wake_up_interruptible(&dev->bulk_in_wait);
}

static ssize_t bulk_in_rcv_io(struct usb_bulk_storage *dev, size_t count)
{
        int rv;

        usb_fill_bulk_urb(dev->bulk_in_urb,
                          dev->udev,
                          usb_rcvbulkpipe(dev->udev, dev->bulk_in_endpointAddr),
                          dev->bulk_in_buffer,
                          min(dev->bulk_in_size, count),
                          bulk_storage_read_callback,
                          dev);
        spin_lock_irq(&dev->err_lock);
        dev->ongoing_read = 1;
        spin_unlock_irq(&dev->err_lock);

        dev->bulk_in_filled = 0;
        dev->bulk_in_copied = 0;

        rv = usb_submit_urb(dev->bulk_in_urb, GFP_KERNEL);
        if (rv < 0) {
                dev_err(&dev->interface->dev,
                        "%s - failed submitting read urb, error %d\n",
                        __func__, rv);
                rv = (rv == -ENOMEM) ? rv : -EIO;
                spin_lock_irq(&dev->err_lock);
                dev->ongoing_read = 0;
                spin_unlock_irq(&dev->err_lock);
        }

        return rv;
}

static ssize_t bulk_in_rcv(struct usb_bulk_storage *dev, struct file *file, char *buffer, size_t count)
{
        int rv;
        bool ongoing_io;

        rv = mutex_lock_interruptible(&dev->io_mutex);
        if (rv < 0)
                return rv;

        if (dev->disconnected) {
                rv = -ENODEV;
                goto exit;
        }

        spin_lock_irq(&dev->err_lock);
        ongoing_io = dev->ongoing_read;
        spin_unlock_irq(&dev->err_lock);

        if (ongoing_io) {
                if (file->f_flags & O_NONBLOCK) {
                        rv = -EAGAIN;
                        goto exit;
                }

                rv = wait_event_interruptible(dev->bulk_in_wait, (!dev->ongoing_read));
                if (rv < 0)
                        goto exit;
        }

        rv = dev->errors;
        if (rv < 0) {
                dev->errors = 0;
                rv = (rv == -EPIPE) ? rv : -EIO;
                goto exit;
        }

        rv = bulk_in_rcv_io(dev, count);
        if (rv < 0)
                goto exit;

        spin_lock_irq(&dev->err_lock);
        ongoing_io = dev->ongoing_read;
        spin_unlock_irq(&dev->err_lock);

        if (ongoing_io) {
                if (file->f_flags & O_NONBLOCK) {
                        rv = -EAGAIN;
                        goto exit;
                }

                rv = wait_event_interruptible(dev->bulk_in_wait, (!dev->ongoing_read));
                if (rv < 0)
                        goto exit;
        }

        if (copy_to_user(buffer, dev->bulk_in_buffer, count))
                rv = -EFAULT;
        else
                rv = count;
        
exit:
        mutex_unlock(&dev->io_mutex);
        return rv;
}


static ssize_t bulk_storage_read(struct file *file, char *buffer, size_t count,
                                loff_t *ppos)
{
        struct usb_bulk_storage *dev = file->private_data;
        int retval = 0;
        char *buf_csw;

        buf_csw = kmalloc(CSW_SIZE, GFP_KERNEL);
        if (buf_csw == NULL) {
                retval = -1;
                goto exit;
        }

        if (count < READ_BYTE_SIZE) {
                pr_info("bulk_storage: too small buffer length: 0x%x", (unsigned int)count);
                retval = -ESIZE;
                goto exit;
        }
        
        retval = bulk_out_snd(dev, file, CMD_READ);
        retval = bulk_in_rcv(dev, file, buffer, CBW_CMD_READ_TXLENGTH);
        retval = bulk_in_rcv(dev, file, buf_csw, CSW_SIZE);

        kfree(buf_csw);
exit:
        return retval;
}

static ssize_t bulk_storage_write(struct file *file, const char *user_buffer,
                                   size_t count, loff_t *ppos)
{
        struct usb_bulk_storage *dev = file->private_data;
        int retval = 0;
        char *buf_csw;

        write_buffer = NULL;

        write_buffer = kmalloc(count, GFP_KERNEL);
        if (write_buffer == NULL) {
                retval = -1;
                goto exit;
        }

        buf_csw = kmalloc(CSW_SIZE, GFP_KERNEL);
        if (buf_csw == NULL) {
                retval = -1;
                kfree(write_buffer);
                goto exit;
        }

        if (count < WRITE_BYTE_SIZE) {
                pr_info("bulk_storage: too small buffer length: 0x%x", (unsigned int)count);
                retval = -ESIZE;
                goto exit;
        }

        if (copy_from_user(write_buffer, user_buffer, count)) {
                retval = -EFAULT;
                kfree(write_buffer);
                kfree(buf_csw);
                goto exit;
        }


        retval = bulk_out_snd(dev, file, CMD_WRITE);
        retval = bulk_out_snd(dev, file, CMD_SNDDATA);
        retval = bulk_in_rcv(dev, file, buf_csw, CSW_SIZE);

        kfree(write_buffer);
        kfree(buf_csw);
exit:
        return count;
}

static int bulk_storage_open(struct inode *inode, struct file *file)
{
        struct usb_bulk_storage *dev;
        struct usb_interface  *interface;
        int subminor;
        int retval = 0;

        subminor = iminor(inode);

        interface = usb_find_interface(&bulk_storage_driver, subminor);
        if (!interface) {
                pr_err("%s - error, can't find device for minor %d\n",
                        __func__, subminor);
                retval = -ENODEV;
                goto exit;
        }

        dev = usb_get_intfdata(interface);
        if (!dev) {
                retval = -ENODEV;
                goto exit;
        }

        retval = usb_autopm_get_interface(interface);
        if (retval) {
                pr_info("Bulk_storage_open: 5 - retval is 0 / success\n");
                goto exit;
        }

        kref_get(&dev->kref);

        file->private_data = dev;

exit:
        return retval;
}

static int bulk_storage_release(struct inode *inode, struct file *file)
{
        struct usb_bulk_storage *dev;
        dev = file->private_data;
        if (dev == NULL)
                return -ENODEV;

        usb_autopm_put_interface(dev->interface);

        kref_put(&dev->kref, bulk_storage_delete);
        return 0;
}

static loff_t bulk_storage_llseek(struct file *file, loff_t offset, int whence)
{
        struct usb_bulk_storage *dev;
        u64 offset_sector;

        dev = file->private_data;
        if (dev == NULL)
                return -ENODEV;

        offset_sector = offset >> 9;

        if (offset_sector > (1UL << 32))
                return -ESIZE;
        
        lbaseek_h = (u8)(offset_sector >> 24);
        lbaseek_mh = (u8)(offset_sector >> 16);
        lbaseek_ml = (u8)(offset_sector >> 8);
        lbaseek_l = (u8)(offset_sector);

        return offset;
}

static const struct file_operations bulk_storage_fops = {
        .owner =        THIS_MODULE,
        .read =         bulk_storage_read,
        .write =        bulk_storage_write,
        .open =         bulk_storage_open,
        .release =      bulk_storage_release,
        .llseek =       bulk_storage_llseek,
};

struct usb_class_driver bulk_storage_class = {
        .name = "bulk%d",
        .fops = &bulk_storage_fops,
        .minor_base = MINOR_BASE,
};

static int bulk_storage_probe(struct usb_interface *interface,
                             const struct usb_device_id *id)
{
        int retval;
        struct usb_bulk_storage *dev;
        struct usb_endpoint_descriptor *bulk_in, *bulk_out;

        dev = kzalloc(sizeof(*dev), GFP_KERNEL);
        if (!dev)
                return -ENOMEM;

        kref_init(&dev->kref);
        sema_init(&dev->limit_sem, WRITES_IN_FLIGHT);
        mutex_init(&dev->io_mutex);
        spin_lock_init(&dev->err_lock);
        init_usb_anchor(&dev->submitted);
        init_waitqueue_head(&dev->bulk_in_wait);
        
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

        retval = usb_register_dev(interface, &bulk_storage_class);
        if (retval) {
                dev_err(&interface->dev,
                        "Not able to get a minor for this device.\n");
                usb_set_intfdata(interface, NULL);
                goto error;
        }

        pr_info("bulk_storage: probe completed without err\n");
        return 0;

error:
        kref_put(&dev->kref, bulk_storage_delete);
        return retval;
}

static void bulk_storage_disconnect(struct usb_interface *interface)
{
        struct usb_bulk_storage *dev;
        int minor = interface->minor;

        dev = usb_get_intfdata(interface);

        usb_deregister_dev(interface, &bulk_storage_class);

        mutex_lock(&dev->io_mutex);
        dev->disconnected = 1;
        mutex_unlock(&dev->io_mutex);
        
        usb_kill_urb(dev->bulk_in_urb);
        usb_kill_anchored_urbs(&dev->submitted);

        kref_put(&dev->kref, bulk_storage_delete);

        dev_info(&interface->dev, "USB simple ahci #%d now disconnected", minor);
}

static void bulk_storage_draw_down(struct usb_bulk_storage *dev)
{
        int time;

        time = usb_wait_anchor_empty_timeout(&dev->submitted, 1000);
        if (!time)
                usb_kill_anchored_urbs(&dev->submitted);
        usb_kill_urb(dev->bulk_in_urb);
}

static int bulk_storage_suspend(struct usb_interface *intf, pm_message_t message)
{
        struct usb_bulk_storage *dev = usb_get_intfdata(intf);

        if (!dev)
                return 0;
        bulk_storage_draw_down(dev);
        return 0;
}

static int bulk_storage_resume(struct usb_interface *intf)
{
        return 0;
}

static int bulk_storage_pre_reset(struct usb_interface *intf)
{
        struct usb_bulk_storage *dev = usb_get_intfdata(intf);

        mutex_lock(&dev->io_mutex);
        bulk_storage_draw_down(dev);
        return 0;
}

static int bulk_storage_post_reset(struct usb_interface *intf)
{
        struct usb_bulk_storage *dev = usb_get_intfdata(intf);

        dev->errors = -EPIPE;
        mutex_unlock(&dev->io_mutex);

        return 0;
}


static struct usb_driver bulk_storage_driver = {
        .name =         "bulk_storage_driver",
        .probe =        bulk_storage_probe,
        .disconnect =   bulk_storage_disconnect,
        .suspend =      bulk_storage_suspend,
        .resume =       bulk_storage_resume,
        .pre_reset =    bulk_storage_pre_reset,
        .post_reset =   bulk_storage_post_reset,
        .id_table =     bulk_storage_idtable,
        .supports_autosuspend = 1,
};

module_usb_driver(bulk_storage_driver);
MODULE_AUTHOR("Soma Nakata");
MODULE_LICENSE("Dual BSD/GPL");
