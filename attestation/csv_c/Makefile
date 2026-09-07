# gmssl path
# Default to the local GmSSL tree built in this environment.
# Override on the command line if you have GmSSL installed elsewhere.
LIBDIR ?= /home/osr/src/fghdotio-gmssl/unpacked/GmSSL-main/
INCDIR ?= /home/osr/src/fghdotio-gmssl/unpacked/GmSSL-main/include/
BIN_DIR ?= ../../bin
ATTESTATION_DIR := ..
CSV_SDK_DIR := $(ATTESTATION_DIR)/csv_sdk
CSV_C_DIR := .
BUILD_DIR := $(BIN_DIR)/.attestation-build
DYNAMIC_OBJ_DIR := $(BUILD_DIR)/dynamic
STATIC_OBJ_DIR := $(BUILD_DIR)/static
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

.PHONY: all clean dynamic_csv_sdk static_csv_sdk vmmcall-get-attestation ioctl-get-attestation verify-attestation get_key ioctl_get_key calc-vm-digest dcu_attestation_demo

CFLAGS := -I$(INCDIR) -I$(ATTESTATION_DIR) -I$(CSV_C_DIR) -L$(LIBDIR) -m64 -mrdrnd -DLOG_ON
STATIC_CFLAGS := -Wl,-rpath,$(LIBDIR),-Bstatic
SHARED_CFLAGS := -Wl,-rpath,$(LIBDIR),-Bdynamic
OS := $(shell grep -i '^name=' /etc/os-release | awk -F '=' '{print $$2}' | tr -d '"' | tr "[:upper:]" "[:lower:]")
$(info Operating System: $(OS))

$(BIN_DIR):
	mkdir -p $@

$(DYNAMIC_OBJ_DIR) $(STATIC_OBJ_DIR): | $(BIN_DIR)
	mkdir -p $@

CSV_SDK_SRCS := $(wildcard $(CSV_SDK_DIR)/*.c)
DYNAMIC_OBJS := $(patsubst $(CSV_SDK_DIR)/%.c,$(DYNAMIC_OBJ_DIR)/%.o,$(CSV_SDK_SRCS))
STATIC_OBJS := $(patsubst $(CSV_SDK_DIR)/%.c,$(STATIC_OBJ_DIR)/%.o,$(CSV_SDK_SRCS))

$(DYNAMIC_OBJ_DIR)/%.o: $(CSV_SDK_DIR)/%.c | $(DYNAMIC_OBJ_DIR)
	gcc -Wall $(CFLAGS) -c -fpic $< -o $@

$(STATIC_OBJ_DIR)/%.o: $(CSV_SDK_DIR)/%.c | $(STATIC_OBJ_DIR)
	gcc -Wall $(CFLAGS) -c $< -o $@

dynamic_csv_sdk: $(DYNAMIC_OBJS) | $(BIN_DIR)
	gcc -Wall $(CFLAGS) -o $(LIBCSV_SO) -shared $(DYNAMIC_OBJS) $(STATIC_CFLAGS) -lcrypto $(SHARED_CFLAGS) -ldl -lpthread

static_csv_sdk: $(STATIC_OBJS) | $(BIN_DIR)
	rm -f $(LIBCSV_A)
	ar -r $(LIBCSV_A) $(STATIC_OBJS)

vmmcall-get-attestation: static_csv_sdk $(CSV_C_DIR)/vmmcall_get_attestation.c | $(BIN_DIR)
	gcc -Wall $(CFLAGS) -o $(VMMCALL_GET_ATTESTATION_BIN) $(CSV_C_DIR)/vmmcall_get_attestation.c -L$(BIN_DIR) $(LIBCSV_A) $(STATIC_CFLAGS) -lcrypto $(SHARED_CFLAGS) -ldl -lpthread

ioctl-get-attestation: static_csv_sdk $(CSV_C_DIR)/ioctl_get_attestation.c | $(BIN_DIR)
ifeq ($(OS),openeuler)
	gcc -Wall $(CFLAGS) -o $(IOCTL_GET_ATTESTATION_BIN) $(CSV_C_DIR)/ioctl_get_attestation.c -L$(BIN_DIR) $(LIBCSV_A) -lcrypto -ldl -static
else
	gcc -Wall $(CFLAGS) -o $(IOCTL_GET_ATTESTATION_BIN) $(CSV_C_DIR)/ioctl_get_attestation.c -L$(BIN_DIR) $(LIBCSV_A) $(STATIC_CFLAGS) -lcrypto $(SHARED_CFLAGS) -ldl -lpthread
endif
	cp $(IOCTL_GET_ATTESTATION_BIN) $(GET_ATTESTATION_BIN)

verify-attestation: static_csv_sdk $(CSV_C_DIR)/verify_attestation.c | $(BIN_DIR)
	gcc -Wall $(CFLAGS) -o $(VERIFY_ATTESTATION_BIN) $(CSV_C_DIR)/verify_attestation.c -L$(BIN_DIR) $(LIBCSV_A) $(SHARED_CFLAGS) -lcrypto $(SHARED_CFLAGS) -ldl -lpthread

get_key: static_csv_sdk $(CSV_C_DIR)/vmmcall_get_key.c | $(BIN_DIR)
	gcc -Wall $(CFLAGS) -o $(GET_KEY_BIN) $(CSV_C_DIR)/vmmcall_get_key.c -L$(BIN_DIR) $(LIBCSV_A) $(STATIC_CFLAGS) -lcrypto $(SHARED_CFLAGS) -ldl -lpthread

ioctl_get_key: static_csv_sdk $(CSV_C_DIR)/ioctl_get_key.c | $(BIN_DIR)
	gcc -Wall $(CFLAGS) -o $(IOCTL_GET_KEY_BIN) $(CSV_C_DIR)/ioctl_get_key.c -L$(BIN_DIR) $(LIBCSV_A) $(STATIC_CFLAGS) -lcrypto $(SHARED_CFLAGS) -ldl -lpthread

calc-vm-digest: $(CSV_C_DIR)/calc_vm_digest.c | $(BIN_DIR)
	gcc -Wall $(CFLAGS) -o $(CALC_VM_DIGEST_BIN) $(CSV_C_DIR)/calc_vm_digest.c $(STATIC_CFLAGS) -lcrypto $(SHARED_CFLAGS)  -ldl -lpthread

dcu_attestation_demo: static_csv_sdk $(CSV_C_DIR)/dcu_attestation_demo.c | $(BIN_DIR)
	gcc -Wall $(CFLAGS) -o $(DCU_ATTESTATION_DEMO_BIN) $(CSV_C_DIR)/dcu_attestation_demo.c -L$(BIN_DIR) $(LIBCSV_A) $(STATIC_CFLAGS) -lcrypto $(SHARED_CFLAGS)  -ldl -lpthread

clean:
	rm -f $(LIBCSV_SO) $(LIBCSV_A) $(VMMCALL_GET_ATTESTATION_BIN) $(IOCTL_GET_ATTESTATION_BIN) $(GET_ATTESTATION_BIN) $(VERIFY_ATTESTATION_BIN) $(GET_KEY_BIN) $(IOCTL_GET_KEY_BIN) $(CALC_VM_DIGEST_BIN) $(DCU_ATTESTATION_DEMO_BIN)
	rm -rf $(BUILD_DIR)

