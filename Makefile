OUTPUT = output

.PHONY := all
all: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	mv *.ko *.mod *.o *.order output/

.PHONY += clean
clean:
	rm $(OUTPUT)/*.ko $(OUTPUT)/*.mod $(OUTPUT)/*.o $(OUTPUT)/*.order
