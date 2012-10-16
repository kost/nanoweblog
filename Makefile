CC=gcc
CFLAGS=-Wall -DHAVE_PWD_H -DHAVE_OPENLOG
nanoweblog: nanoweblog.c
	wc -l nanoweblog.c
	$(CC) $(CFLAGS) nanoweblog.c -o nanoweblog

lines:
	wc -l nanoweblog.c

flaws: flawfinder rats

flawfinder:
	flawfinder nanoweblog.c

rats:
	rats nanoweblog.c

