#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "csv_status.h"
#include "csv_sdk/csv_sdk.h"


static int load_nonce_from_file(unsigned char *nonce, const char *path, unsigned int nonce_len)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    int total = 0, n;
    while ((unsigned int)total < nonce_len) {
        n = read(fd, nonce + total, nonce_len - total);
        if (n <= 0) {
            close(fd);
            return -1;
        }
        total += n;
    }

    close(fd);
    return 0;
}

static int save_data_to_file(unsigned char *data, unsigned int data_len, const char *path)
{
    if (!data) {
        printf("no data\n");
        return -1;
    }
    if (!path || !*path) {
        printf("no file\n");
        return -1;
    }

    if (!data_len) {
        printf("data length is 0\n");
        return -1;
    }

    int fd = open(path, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (fd < 0) {
        printf("open file %s fail %d, error (%s)\n", path, fd, strerror(errno));
        return fd;
    }

    int len = 0, n;

    while (len < data_len) {
        n = write(fd, data + len, data_len - len);
        if (n == -1) {
            printf("write file error\n");
            close(fd);
            return n;
        }
        len += n;
    }

    close(fd);

    return 0;
}

int main()
{
    int ret;
    uint8_t  nonce[GUEST_ATTESTATION_NONCE_SIZE] = {0};

    unsigned int len = sizeof(struct csv_attestation_report);

    unsigned char* report_buf = (unsigned char*)malloc(len);

    if (load_nonce_from_file(nonce, ATTESTATION_NONCE_FILE, GUEST_ATTESTATION_NONCE_SIZE) != 0) {
        gen_random_bytes(nonce, GUEST_ATTESTATION_NONCE_SIZE);
    } else {
        logcat("\nLoaded nonce from %s\n", ATTESTATION_NONCE_FILE);
    }

    ret = ioctl_get_attestation_report(report_buf, len, nonce, GUEST_ATTESTATION_NONCE_SIZE);
    if (ret) {
        printf("get report fail\n");
        free(report_buf);
        return -1;
    }

    logcat("\nSave attestation report to %s\n", ATTESTATION_REPORT_FILE);
    ret = save_data_to_file(report_buf, sizeof(struct csv_attestation_report), ATTESTATION_REPORT_FILE);
    if (ret) {
        printf("save report fail\n");
        free(report_buf);
        return -1;
    }

    logcat("\nSave nonce to %s\n", ATTESTATION_NONCE_FILE);
    ret = save_data_to_file(nonce, GUEST_ATTESTATION_NONCE_SIZE, ATTESTATION_NONCE_FILE);
    if (ret) {
        printf("save nonce fail\n");
        free(report_buf);
        return -1;
    }

    printf("done\n");

    free(report_buf);
    return ret;
}
