#include <stdio.h>
#include <stdlib.h>

int main()
{
        FILE *fp, *log;
        char *buf;
        fp = fopen("/dev/sahci0", "rb");
        if(fp == NULL) {
                printf("Error during open\n");
                return -1;
        }

        buf = malloc(0x1000);
        fread(buf, 1, 200, fp);
        fclose(fp);

        log = fopen("log_verify.bin", "wb");
        fwrite(buf, 1, 200, log);
        fclose(log);
        return 0;
}
