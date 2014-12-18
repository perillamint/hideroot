obj-m := hideroot.o
hideroot-objs += main.o
hideroot-objs += dumpcode.o
hideroot-objs += mmuhack.o
hideroot-objs += gphook.o

# Make sure the whitespaces before the "make" commands below are real tabs!
all:
	make -C $(KDIR) EXTRA_CFLAGS=-fno-pic M=$(PWD) modules
 
clean:
	make -C $(KDIR) M=$(PWD) clean
