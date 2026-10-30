DRIVER = keystone-driver.ko

ifneq ($(KERNELRELEASE),)
	keystone-driver-y := \
		keystone.o \
		keystone-page.o \
		keystone-ioctl.o \
		keystone-group.o \
		keystone-enclave.o \
	  keystone-sbi.o
	obj-m += keystone-driver.o

ifeq ($(KEYSTONE_SDK_DIR),)
    KEYSTONE_SDK_DIR := $(abspath $(srctree)/../buildroot/package/keystone-sdk)
endif

ifeq ($(wildcard $(KEYSTONE_SDK_DIR)/include/shared/sm_call.h),)
    $(error Keystone SDK shared headers not found under KEYSTONE_SDK_DIR=$(KEYSTONE_SDK_DIR))
endif

	ccflags-y := -I$(KEYSTONE_SDK_DIR)/include/shared
else

PWD := $(shell pwd)
LINUXSRC := $(PWD)/../linux

default:
	$(MAKE) -C $(LINUXSRC) ARCH=riscv CROSS_COMPILE=riscv$(KEYSTONE_BITS)-unknown-linux-gnu- M=$(PWD)

endif

clean:
	rm -rvf *.o *.ko *.order *.symvers *.mod.c .tmp_versions .*o.cmd
