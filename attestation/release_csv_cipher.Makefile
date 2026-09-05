# gmssl path
LIBDIR = /opt/gmssl/lib/
INCDIR = /opt/gmssl/include/

all: static_csv_sdk demo

CFLAGS := -I$(INCDIR) -L$(LIBDIR) -m64 -mrdrnd
CFLAGS += $(CFLAG)
STATIC_CFLAGS := -Wl,-rpath,$(LIBDIR),-Bstatic
SHARED_CFLAGS := -Wl,-rpath,$(LIBDIR),-Bdynamic

OS := $(shell grep -i '^name=' /etc/os-release | awk -F '=' '{print $$2}' | tr -d '\"' | tr "[:upper:]" "[:lower:]")
$(info Operating System: $(OS))

dynamic_csv_sdk:
	gcc -Wall $(CFLAGS) -c -fpic csv_status.c
	gcc -Wall $(CFLAGS) -o libcsv_cipher.so -shared *.o $(STATIC_CFLAGS) -lcrypto $(SHARED_CFLAGS) -ldl -lpthread
	rm *.o

static_csv_sdk:
	gcc -Wall $(CFLAGS) -c csv_status.c
	ar -r libcsv_cipher.a *.o
	rm *.o

demo:
ifeq ($(OS),openeuler)
	gcc -Wall $(CFLAGS) -o demo demo.c -L. libcsv_cipher.a  -lcrypto  -ldl -lpthread -static
else
	gcc -Wall $(CFLAGS) -o demo demo.c -L. libcsv_cipher.a $(STATIC_CFLAGS) -lcrypto $(SHARED_CFLAGS) -ldl -lpthread

endif

clean:
	rm demo libcsv_cipher.*


