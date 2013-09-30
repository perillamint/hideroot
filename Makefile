obj-m := hideroot.o
hideroot-objs += main.o

KDIR = /home/maneulyori/Optimus_G_dev/garlickernel-lgog/
#KDIR = /home/maneulyori/galaxynote
export CROSS_COMPILE := /home/maneulyori/arm-eabi-4.6/bin/arm-eabi-
export ARCH := arm

# Make sure the whitespaces before the "make" commands below are real tabs!
all:
	make -C $(KDIR) EXTRA_CGLAGS=-fno-pic M=$(PWD) modules
 
clean:
	make -C $(KDIR) M=$(PWD) clean
