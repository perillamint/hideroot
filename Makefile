obj-m := hideroot.o
hideroot-objs += main.o
hideroot-objs += mmuhack.o
hideroot-objs += dumpcode.o

# Make sure the whitespaces before the "make" commands below are real tabs!
all:
	make -C $(KDIR) EXTRA_CGLAGS=-fno-pic M=$(PWD) modules
 
clean:
	make -C $(KDIR) M=$(PWD) clean
