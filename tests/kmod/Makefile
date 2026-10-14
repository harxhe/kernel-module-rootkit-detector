# Build the harmless demo module against the running kernel's headers:
#   sudo apt install build-essential linux-headers-$(uname -r)
#   make -C tests/kmod
obj-m += test_rogue.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
