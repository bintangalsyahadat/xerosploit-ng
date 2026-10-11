all:

clean:

install:
	chmod 755 banner.py
	chmod 755 install.py
	chmod 755 run.sh
	chmod 755 xerosploit.py
	mkdir -p $(DESTDIR)/opt/xerosploit/
	mkdir -p $(DESTDIR)/opt/xerosploit/lib/
	mkdir -p $(DESTDIR)/opt/xerosploit/tools/files/
	mkdir -p $(DESTDIR)/opt/xerosploit/tools/log/
	mkdir -p $(DESTDIR)/opt/xerosploit/tools/tmp/
	mkdir -p $(DESTDIR)/usr/share/doc/xerosploit/
	mkdir -p $(DESTDIR)/usr/bin/
	cp banner.py $(DESTDIR)/opt/xerosploit/
	cp install.py $(DESTDIR)/opt/xerosploit/
	cp LICENSE $(DESTDIR)/opt/xerosploit/
	cp Makefile $(DESTDIR)/opt/xerosploit/
	cp README.md $(DESTDIR)/opt/xerosploit/
	cp README.md $(DESTDIR)/usr/share/doc/xerosploit/
	cp run.sh $(DESTDIR)/opt/xerosploit/
	cp run.sh $(DESTDIR)/usr/bin/
	cp xerosploit.py $(DESTDIR)/opt/xerosploit/
	cp -r lib $(DESTDIR)/opt/xerosploit/
	if [ -d modules ]; then cp -r modules $(DESTDIR)/opt/xerosploit/; fi
	cp -r tools/files $(DESTDIR)/opt/xerosploit/tools/
	cp -r tools/log $(DESTDIR)/opt/xerosploit/tools/
	if [ -d tools/tmp ]; then cp -r tools/tmp $(DESTDIR)/opt/xerosploit/tools/; fi
