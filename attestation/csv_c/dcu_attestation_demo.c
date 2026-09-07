#include <stdio.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/ioctl.h>
#include <errno.h>
#include <time.h>

#include "csv_status.h"

#define   CMD_ATTESTATION                    0x0
#define   GUEST_ATTESTATION_RESERVED_SIZE    128

extern int load_hrk_file(char *filename,void *buff,size_t len);
extern int verify_hsk_cert_signature(CHIP_ROOT_CERT_t *hrk,CHIP_ROOT_CERT_t *hsk);
extern int verify_cek_signature(CHIP_ROOT_CERT_t *hsk, CSV_CERT_t *cek);
extern int load_hsk_cek_file(char *chip_id,void *hsk,size_t hsk_len,void *cek,size_t cek_len);
extern int csv_cert_verify(const char *data, uint32_t datalen, ecc_signature_t *signature, ecc_pubkey_t *pubkey);
extern int verify_hrk_cert_signature(CHIP_ROOT_CERT_t *hrk);

#define  PAGE_SIZE    4096

typedef struct attestation_request {
    uint8_t  user_data[GUEST_ATTESTATION_DATA_SIZE];
}attestation_request_t;

typedef struct attestation_report {
    uint32_t       version;
    uint8_t        chip_id[CHIP_KEY_ID_LEN];
    uint8_t        user_data[GUEST_ATTESTATION_DATA_SIZE];
    hash_block_t   measure;
    uint8_t        reserved[GUEST_ATTESTATION_RESERVED_SIZE];
    uint32_t       sig_algo;
    uint32_t       sig_usage;
    union {
        uint32_t        sig1[ECC_POINT_SIZE*2/SIZE_INT32];
        ecc_signature_t ecc_sig1;
    };
}attestation_report_t;

typedef struct attestation_response {
    uint32_t  report_size;
    uint8_t   reserved[28];
    attestation_report_t report;
}attestation_response_t;

struct mkfd_ioctl_security_attestation_args {
    uint32_t gpu_id;
    //command id
    uint32_t cmd_id;
    // Message version number(default 1)
    uint32_t version;
    // Request structure address
    void *request_data;
    // Request structure size
    uint64_t request_size;
    // Response structure address
    void *response_data;
    // Response structure size
    uint64_t response_size;
    // Firmware error address.
    uint64_t fw_err;
};

#define MKFD_IOCTL_BASE 'M'
#define MKFD_IO(nr)             _IO(MKFD_IOCTL_BASE, nr)
#define MKFD_IOR(nr, type)      _IOR(MKFD_IOCTL_BASE, nr, type)
#define MKFD_IOW(nr, type)      _IOW(MKFD_IOCTL_BASE, nr, type)
#define MKFD_IOWR(nr, type)     _IOWR(MKFD_IOCTL_BASE, nr, type)

#define MKFD_IOC_SECURITY_ATTESTATION   \
            MKFD_IOWR(0x17, struct mkfd_ioctl_security_attestation_args)

static int num_subdirs(char *dirpath, char *prefix)
{
    int count = 0;
    DIR *dirp;
    struct dirent *dir;
    int prefix_len = strlen(prefix);

    dirp = opendir(dirpath);
    if (dirp) {
        while ((dir = readdir(dirp)) != 0) {
            if ((strcmp(dir->d_name, ".") == 0) ||
                (strcmp(dir->d_name, "..") == 0))
                continue;
            if (prefix_len && strncmp(dir->d_name, prefix, prefix_len))
                continue;
            count++;
        }
        closedir(dirp);
    }

    return count;
}

static int topology_sysfs_get_gpu_id(uint32_t sysfs_node_id, uint32_t *gpu_id)
{
    FILE *fd;
    char path[256];
    int ret = 0;

    snprintf(path, 256, "%s/%d/gpu_id", "/sys/devices/virtual/kfd/kfd/topology/nodes", sysfs_node_id);
    fd = fopen(path, "r");
    if (!fd)
        return -1;
    if (fscanf(fd, "%ul", gpu_id) != 1)
        ret = -1;
    fclose(fd);

    return ret;
}


void hex_dump(const uint8_t* addr, uint32_t len)
{
    int i;

    for (i = 0; i < len; i++) {
        if (i % 16 == 15) {
            logcat(" %02X\n", *addr);
        } else {
            logcat(" %02X", *addr);
        }
        addr++;
    }
    if (i % 16 != 0) {
        logcat("\n");
    }
}


int verify_chain(CHIP_ROOT_CERT_t* hrk, CHIP_ROOT_CERT_t * hsk, CSV_CERT_t *cek)
{
    int ret = 0;

    if (hsk->key_usage != KEY_USAGE_TYPE_HSK) {  // Variable size
        logcat("hsk.cert key_usage field isn't correct, please use command parse_cert to check hsk.cert\n");
        goto finish;
    }

    if (cek->pubkey_usage != KEY_USAGE_TYPE_CEK) {
        logcat("cek.cert pub_key_usage field doesn't correct, please use command parse_cert to check cek.cert\n");
        goto finish;
    }

    if (cek->sig1_usage != KEY_USAGE_TYPE_HSK) {
        logcat("cek.cert sig_1_usage field isn't correct, please use command parse_cert to check cek.cert\n");
        goto finish;
    }

    if (cek->sig2_usage != KEY_USAGE_TYPE_INVALID) {
        logcat("cek.cert sig_2_usage field isn't correct, please use command parse_cert to check cek.cert\n");
        goto finish;
    }

    ret = verify_hsk_cert_signature(hrk, hsk);
    if(ret){
        logcat("hrk pubkey verify hsk cert failed\n");
        goto finish;
    }
    logcat("hrk pubkey verify hsk cert successful\n\n");
    ret = verify_cek_signature(hsk, cek);
    if(ret){
        logcat("hsk pubkey verify cek cert failed\n");
        goto finish;
    }
    logcat("hsk pubkey verify cek cert successful\n\n");

    ret = 0;
    return ret;

finish:
    ret = -1;
    return ret;
}

/*
 * 1. using the chip id in the report to download the hsk and cek
 * 2. verify the hsk (by the hrk)
 * 3. verify the cek (by the hsk)
 * 4. verify the report (by the cek)
 */int verify_report(CHIP_ROOT_CERT_t* hrk, attestation_report_t * report)
{
    CSV_CERT_t cek;
    CHIP_ROOT_CERT_t hsk;
    int ret = 0;
    char chip_string[64] = { 0 };
    int i = 0;

    for(i = 0; i < sizeof(report->chip_id) - 1; i++) {
        if(report->chip_id[i] != ' ')
            break;
    }

    memcpy(chip_string, &report->chip_id[i], sizeof(report->chip_id) - i);
    logcat(" Loading HSK(Hygon Signing Key) certificate and  CEK(Chip Endorsement Key) by chip id \n");
    logcat(" %s\n\n", chip_string);
    ret = load_hsk_cek_file(chip_string, &hsk,sizeof(CHIP_ROOT_CERT_t),&cek,sizeof(CSV_CERT_t));
    if(ret) {
        logcat("Error:load hsk-cek cert failed\n");
        goto finish;
    }

    /* verify the hsk and cek */
    ret = verify_chain(hrk, &hsk, &cek);
    if(ret) {
        logcat("Error:hsk or cek error\n");
        goto finish;
    }

    logcat("Start to verify report by CEK \n\n");
    ret = csv_cert_verify((const char *)report, sizeof(*report) - sizeof(report->ecc_sig1),
                          &report->ecc_sig1, &cek.ecc_pubkey);
    logcat("cek verify report %s\n", ret ? "fail" : "success");

    return ret;

finish:
    ret = -1;
    return ret;
}


/*
 * download and verify root certificate
 */
int verify_root_cert(CHIP_ROOT_CERT_t* hrk)
{
    int ret = 0;

    logcat(" Loading HRK(Hyong Root Key) certificate \n\n");
    ret = load_hrk_file(HRK_FILENAME,hrk,sizeof(CHIP_ROOT_CERT_t));
    if(ret) {
        logcat("hrk.cert doesn't exist or size isn't correct\n");
        ret = -1;
        goto finish;
    }

    if(hrk->key_usage != KEY_USAGE_TYPE_HRK) {
        logcat("hrk.cert key_usage field isn't correct, please use command parse_cert to check hrk.cert\n");
        ret = -1;
        goto finish;
    }

    ret = verify_hrk_cert_signature(hrk);
    if(ret){
        logcat("hrk pubkey verification failed\n");
        ret = -1;
        goto finish;
    }
    logcat("hrk pubkey verified successful\n");

finish:
    return ret;
}


/* print the report information */
void log_report(attestation_report_t* report)
{
    char chipid_str[64] = {0};

    if (report == NULL) {
        logcat("report is NULL\n");
        return;
    }

    logcat("user data\n");
    hex_dump(report->user_data, sizeof(report->user_data));
    memcpy(chipid_str, report->chip_id, sizeof(report->chip_id));
    logcat("chip_id \n");
    logcat("%s\n", chipid_str);
    logcat("signature r\n");
    hex_dump((uint8_t*)report->ecc_sig1.sig_r, ECC_LEN);
    logcat("signature s\n");
    hex_dump((uint8_t*)report->ecc_sig1.sig_s, ECC_LEN);
    logcat(" \n\n");

    return ;
}

int set_attestation_args(struct mkfd_ioctl_security_attestation_args *arg, int gpu_id)
{
    attestation_request_t  *request = NULL;

    arg->gpu_id = gpu_id;
    arg->cmd_id = CMD_ATTESTATION;
    arg->version = 0x1;
    arg->request_data = (void *)malloc(PAGE_SIZE);
    arg->request_size = PAGE_SIZE;
    memset(arg->request_data, 0, arg->request_size);
    request = (attestation_request_t*)arg->request_data;
    srand(time(NULL));
    gen_random_bytes(request->user_data, sizeof(request->user_data));
    logcat("\n\nGenerated random number for DCU report request\n");
    hex_dump(request->user_data, sizeof(request->user_data));

    arg->response_data = (void *)malloc(PAGE_SIZE);
    arg->response_size = PAGE_SIZE;
    memset(arg->response_data, 0, arg->response_size);

    return 0;
}

/*
 * This demo requests the DCU to sign the attestation report by the private DCU CEK.
 * The demo verifies the signature by the public DCU CEK.
 * The important info to be signed is DCU chip id and DCU measurement.
 */

int main()
{
    int fd  = -1;
    int ret = 0;
    uint32_t node = 0;
    uint32_t num_node = 0;
    uint32_t gpu_id = 0;
    struct mkfd_ioctl_security_attestation_args arg;
    attestation_request_t  *request;
    attestation_response_t  *response;
    uint32_t dcu_index = 1;
    /* hrk -> hsk -> cek */
    CHIP_ROOT_CERT_t hrk;
    int root_cert_verified = 0;

    fd = open("/dev/mkfd", O_RDWR | O_CLOEXEC);

    if (fd == -1) {
        logcat("open /dev/mkfd fail error: %s, there is no dcu found\n", strerror(errno));
        return -1;
    }

    num_node = num_subdirs("/sys/devices/virtual/kfd/kfd/topology/nodes", "");
    for (node = 0; node < num_node; node++){
        topology_sysfs_get_gpu_id(node, &gpu_id);
        if (gpu_id <= 0)
            continue;

        memset(&arg, 0, sizeof(struct mkfd_ioctl_security_attestation_args));
        set_attestation_args(&arg, gpu_id);

        ret = ioctl(fd, MKFD_IOC_SECURITY_ATTESTATION, &arg);

        if (ret == -1) {
            logcat("exec cmd error!\n");
            return -1;
        }
        if (arg.fw_err != 0) {
            logcat("DCU %d fail to sign the report\n", dcu_index);
            goto l_free;
        }
        response = (attestation_response_t*)arg.response_data;
        logcat(" \n========= DCU %d report information ============ \n", dcu_index++);
        logcat("Node %d gpu: %d\n", node, gpu_id);
        if (arg.fw_err != 0) {
            logcat("fail to get report from DCU\n");
            goto l_free;
        }
        log_report(&response->report);

        request = arg.request_data;
        if (memcmp(request->user_data, response->report.user_data, sizeof(request->user_data))) {
           logcat("the user data in request is different to the user data in response, error!\n");
           goto finish;
        }

        if (!root_cert_verified) {
            verify_root_cert(&hrk);
            root_cert_verified = 1;
        }

        verify_report(&hrk, &response->report);
l_free:
        free(arg.request_data);
        free(arg.response_data);
    }

    close(fd);

finish:
    return 0;
}
