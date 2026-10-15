# Build the harmless demo module against the running kernel's headers:
#   sudo apt install build-essential linux-headers-$(uname -r)
#   make -C tests/kmod
#
# $(CURDIR), not $(PWD): `make -C dir` changes make's directory but not the
# PWD environment variable, which would point kbuild at the wrong folder.
KDIR ?= /lib/modules/$(shell uname -r)/build

obj-m += test_rogue.o

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules
	@test -f $(CURDIR)/test_rogue.ko || { echo "error: test_rogue.ko was not built"; exit 1; }
	@echo "built $(CURDIR)/test_rogue.ko"

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
