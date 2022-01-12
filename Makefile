BINDIR := /usr/bin
SCRIPT := jwt_tool.py

# install by default
all: install

install:
	# copy $(SCRIPT) file to /usr/bin/$(SCRIPT), which should be in path
	cp $(SCRIPT) $(DESTDIR)$(BINDIR)/jwt-tool
	# Mark script as executable
	chmod 0755 $(DESTDIR)$(BINDIR)/jwt-tool

uninstall:
	rm -rf $(DESTDIR)$(BINDIR)/jwt-tool

.PHONY: all install uninstall
