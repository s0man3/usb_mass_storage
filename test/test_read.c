#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int main()
{
        int fd;
        FILE *fp;
        char *buf;

        buf = malloc(0x1000);

        fd = open("/dev/bulk0", O_RDONLY);
        if (fd == -1) {
                printf("error during open\n");
                return -1;
        }

        read(fd, buf, 0x1000);
        close(fd);

        fp = fopen("../log/read_log_v2.bin", "wb");
        fwrite(buf, 1, 0x1000, fp);
        fclose(fp);

        return 0;
}
