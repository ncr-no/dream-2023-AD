SERVICE := digital-seconds-ago
DESTDIR ?= dist_root
SERVICEDIR ?= /srv/$(SERVICE)

.PHONY: build install

build:
	$(MAKE) -C src
clear:
	$(MAKE) -C src clear
install: build
	mkdir -p $(DESTDIR)$(SERVICEDIR)
	cp src/digital-seconds-ago $(DESTDIR)$(SERVICEDIR)/
	mkdir -p $(DESTDIR)/etc/systemd/system
	cp src/digital-seconds-ago@.service $(DESTDIR)/etc/systemd/system/
	cp src/digital-seconds-ago.socket $(DESTDIR)/etc/systemd/system/
	cp src/system-digital-seconds-ago.slice $(DESTDIR)/etc/systemd/system/
