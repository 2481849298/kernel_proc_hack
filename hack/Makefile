MODULE_NAME := entryi
RESMAN_CORE_OBJS:= init.o
RESMAN_GLUE_OBJS:= 
ifneq ($(KERNELRELEASE),)
	obj-m := $(MODULE_NAME).o
	$(MODULE_NAME)-objs:=$(RESMAN_GLUE_OBJS) $(RESMAN_CORE_OBJS)
else
	KDIR := /root/kernel-next/out
all:
	make -j$(nproc) -C $(KDIR) M=$(shell pwd) modules
	rm -rf *.o *.mod .*.*.cmd *.mod.o *.mod.c *.symvers *.order .tmp_versions

clean:
	rm -rf *.ko *.o *.mod .*.*.cmd *.mod.o *.mod.c *.symvers *.order .tmp_versions
endif	