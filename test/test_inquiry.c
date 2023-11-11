#include <stdio.h>
#include <stdlib.h>

int main()
{
        FILE *fp;
        char *buf;
        fp = fopen("/dev/sahci0", "rb");
        if(fp == NULL) {
                printf("Error during open\n");
                return -1;
        }

        buf = malloc(0x1000);
        fread(buf, 1, 200, fp);
        fclose(fp);

        return 0;
}
