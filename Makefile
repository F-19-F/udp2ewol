.PHONY: clean uninstall

prefix ?= /usr
exec_prefix ?= $(prefix)
bindir ?= $(exec_prefix)/bin

src = udp2ewol.c
bin = udp2ewol
tgt = $(DESTDIR)$(bindir)/udp2ewol

all: $(bin)


$(bin): $(src)
	gcc $(src) -o $(bin)
$(tgt): $(bin)
	cp udp2ewol $(DESTDIR)$(bindir)
	cp init.d /etc/init.d/udp2ewol

clean:
	rm $(bin)

install: $(tgt)

uninstall:
	rm $(tgt) /etc/init.d/udp2ewol