# gmssl path
# Default to the local GmSSL tree built in this environment.
# Override on the command line if you have GmSSL installed elsewhere.
LIBDIR ?= /home/osr/src/fghdotio-gmssl/unpacked/GmSSL-main/
INCDIR ?= /home/osr/src/fghdotio-gmssl/unpacked/GmSSL-main/include/
BIN_DIR ?= ../bin
ATTESTATION_DIR := ./
CSV_SDK_DIR := $(ATTESTATION_DIR)/csv_sdk
CSV_CIPHER_DIR := $(ATTESTATION_DIR)/csv_cipher
LIBCSV_SO := $(BIN_DIR)/libcsv.so
LIBCSV_A := $(BIN_DIR)/libcsv.a
VMMCALL_GET_ATTESTATION_BIN := $(BIN_DIR)/vmmcall-get-attestation
IOCTL_GET_ATTESTATION_BIN := $(BIN_DIR)/ioctl-get-attestation
GET_ATTESTATION_BIN := $(BIN_DIR)/get-attestation
VERIFY_ATTESTATION_BIN := $(BIN_DIR)/verify-attestation
GET_KEY_BIN := $(BIN_DIR)/get_key
IOCTL_GET_KEY_BIN := $(BIN_DIR)/ioctl_get_key
CALC_VM_DIGEST_BIN := $(BIN_DIR)/calc-vm-digest
DCU_ATTESTATION_DEMO_BIN := $(BIN_DIR)/dcu_attestation_demo

all: dynamic_csv_sdk static_csv_sdk vmmcall-get-attestation ioctl-get-attestation verify-attestation get_key ioctl_get_key calc-vm-digest dcu_attestation_demo

CFLAGS := -I$(INCDIR) -I$(ATTESTATION_DIR) -L$(LIBDIR) -m64 -mrdrnd -DLOG_ON
STATIC_CFLAGS := -Wl,-rpath,$(LIBDIR),-Bstatic
SHARED_CFLAGS := -Wl,-rpath,$(LIBDIR),-Bdynamic
OS := $(shell grep -i '^name=' /etc/os-release | awk -F '=' '{print $$2}' | tr -d '"' | tr "[:upper:]" "[:lower:]")
$(info Operating System: $(OS))

$(BIN_DIR):
	mkdir -p $@

dynamic_csv_sdk: | $(BIN_DIR)
	gcc -Wall $(CFLAGS) -c -fpic csv_sdk/*.c
	gcc -Wall $(CFLAGS) -o $(LIBCSV_SO) -shared *.o $(STATIC_CFLAGS) -lcrypto $(SHARED_CFLAGS) -ldl -lpthread
	rm *.o

static_csv_sdk: | $(BIN_DIR)
	gcc -Wall $(CFLAGS) -c csv_sdk/*.c
	ar -r $(LIBCSV_A) *.o
	rm *.o

vmmcall-get-attestation: static_csv_sdk vmmcall_get_attestation.c | $(BIN_DIR)
	gcc -Wall $(CFLAGS) -o $(VMMCALL_GET_ATTESTATION_BIN) vmmcall_get_attestation.c -L$(BIN_DIR) $(LIBCSV_A) $(STATIC_CFLAGS) -lcrypto $(SHARED_CFLAGS) -ldl -lpthread

ioctl-get-attestation: static_csv_sdk ioctl_get_attestation.c | $(BIN_DIR)
ifeq ($(OS),openeuler)
	gcc -Wall $(CFLAGS) -o $(IOCTL_GET_ATTESTATION_BIN) ioctl_get_attestation.c -L$(BIN_DIR) $(LIBCSV_A) -lcrypto -ldl -static
else
	gcc -Wall $(CFLAGS) -o $(IOCTL_GET_ATTESTATION_BIN) ioctl_get_attestation.c -L$(BIN_DIR) $(LIBCSV_A) $(STATIC_CFLAGS) -lcrypto $(SHARED_CFLAGS) -ldl -lpthread
endif
	cp $(IOCTL_GET_ATTESTATION_BIN) $(GET_ATTESTATION_BIN)

verify-attestation: static_csv_sdk verify_attestation.c | $(BIN_DIR)
	gcc -Wall $(CFLAGS) -o $(VERIFY_ATTESTATION_BIN) verify_attestation.c -L$(BIN_DIR) $(LIBCSV_A) $(SHARED_CFLAGS) -lcrypto $(SHARED_CFLAGS) -ldl -lpthread

get_key: static_csv_sdk vmmcall_get_key.c | $(BIN_DIR)
	gcc -Wall $(CFLAGS) -o $(GET_KEY_BIN) vmmcall_get_key.c -L$(BIN_DIR) $(LIBCSV_A) $(STATIC_CFLAGS) -lcrypto -L$(BIN_DIR) -lcsv $(SHARED_CFLAGS) -ldl -lpthread

ioctl_get_key: static_csv_sdk ioctl_get_key.c | $(BIN_DIR)
	gcc -Wall $(CFLAGS) -o $(IOCTL_GET_KEY_BIN) ioctl_get_key.c -L$(BIN_DIR) $(LIBCSV_A) $(STATIC_CFLAGS) -lcrypto $(SHARED_CFLAGS) -ldl -lpthread

calc-vm-digest: calc_vm_digest.c | $(BIN_DIR)
	gcc -Wall $(CFLAGS) -o $(CALC_VM_DIGEST_BIN) calc_vm_digest.c $(STATIC_CFLAGS) -lcrypto $(SHARED_CFLAGS)  -ldl -lpthread

dcu_attestation_demo: static_csv_sdk dcu_attestation_demo.c | $(BIN_DIR)
	gcc -Wall $(CFLAGS) -o $(DCU_ATTESTATION_DEMO_BIN) dcu_attestation_demo.c -L$(BIN_DIR) $(LIBCSV_A) $(STATIC_CFLAGS) -lcrypto $(SHARED_CFLAGS)  -ldl -lpthread

clean:
	rm -f $(LIBCSV_SO) $(LIBCSV_A) $(VMMCALL_GET_ATTESTATION_BIN) $(IOCTL_GET_ATTESTATION_BIN) $(GET_ATTESTATION_BIN) $(VERIFY_ATTESTATION_BIN) $(GET_KEY_BIN) $(IOCTL_GET_KEY_BIN) $(CALC_VM_DIGEST_BIN) $(DCU_ATTESTATION_DEMO_BIN)

release_csv_cipher:
	rm -rf $(CSV_CIPHER_DIR)
	mkdir $(CSV_CIPHER_DIR)
	cp csv_status.h demo.c $(CSV_CIPHER_DIR)
	cp release_csv_cipher.Makefile $(CSV_CIPHER_DIR)/Makefile
	cp $(CSV_SDK_DIR)/csv_status.c $(CSV_CIPHER_DIR)
