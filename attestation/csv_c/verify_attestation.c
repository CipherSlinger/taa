#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "openssl/err.h"

#include "csv_status.h"
#include "csv_sdk/csv_sdk.h"

static void usage(void)
{
    printf("Usage:\n");
    printf("1) Only verify the attestation report and do not verify certificate chain:\n");
    printf("./verify_attestation false\n\n");
    printf("2) To verify the attestation report and hygon certificate chain\n");
    printf("./verify_attestation true\n\n");
    printf("3) To verify attestation report, hygon certificate chain and OCA sigunature in PEK cert, give the filename of OCA cert on the third parameter: \n");
    printf("./verify_attestation true the_oca_cert_file_name \n\n");

}




static int load_data_from_file(const char *path, void *buff,size_t len)
{
    if (!path || !*path) {
        printf("no file\n");
        return -ENOENT;
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("open file %s fail %s\n", path, strerror(errno));
        return fd;
    }

    int rlen = 0, n;

    while (rlen < len) {
        n = read(fd, buff + rlen,len);
        if (n == -1) {
            printf("read file error\n");
            close(fd);
            return n;
        }
        if (!n) {
            break;
        }
        rlen += n;
    }

    close(fd);

    return 0;
}

int main(int argc,char *argv[])
{
    int ret = 0;
    int verify_chain;
    uint8_t  nonce[GUEST_ATTESTATION_NONCE_SIZE] = {0};
    unsigned int len = 0;
    unsigned char * report_buf = NULL;
    CSV_CERT_t oca_cert ;

    if(argc < 2){
        printf("Error:lack one parameter\n");
        usage();
        return -1;
    }

    if(!strncasecmp(argv[1],"true",4)){
        verify_chain = 1;
        if (argc == 3) {
            external_oca_file = argv[2];
        }
    }else if(!strncasecmp(argv[1],"false",5)){
        verify_chain = 0;
    }else{
        printf("Error:Invalid parameter\n");
        return -1;
    }

    len = sizeof(struct csv_attestation_report);

    report_buf = (unsigned char*)malloc(len);

    printf("load attestation report from %s\n", ATTESTATION_REPORT_FILE);
    ret = load_data_from_file(ATTESTATION_REPORT_FILE, report_buf, len);
    if (ret) {
        printf("load report from file %s fail\n", ATTESTATION_REPORT_FILE);
        return ret;
    }

    ret = verify_attestation_report(report_buf, len, verify_chain);
    if (ret) {
        printf("verify report fail\n");
        free(report_buf);
        return -1;
    }

    if (access(ATTESTATION_NONCE_FILE, F_OK) == 0) {
        printf("\nload original nonce value from %s\n", ATTESTATION_NONCE_FILE);
        ret = load_data_from_file(ATTESTATION_NONCE_FILE, nonce, GUEST_ATTESTATION_NONCE_SIZE);
        if (ret) {
            printf("load report from file %s fail\n", ATTESTATION_NONCE_FILE);
            free(report_buf);
            return ret;
        }

        if (memcmp(nonce, g_mnonce, GUEST_ATTESTATION_NONCE_SIZE)) {
        printf("the nonce in request is different to the nonce in response, error!\n");
        free(report_buf);
        return -1;
        } else {
            printf("nonce is correct! \n\n");
        }
    }

    if (external_oca_file) {
     /* everything has been verified,
     * save the OCA pubkey to openssl readable file for comparison
     */
        if(!load_data_from_file(external_oca_file, &oca_cert, sizeof(oca_cert))) {
            if (!save_csv_pubkey_to_pem_file(&oca_cert.ecc_pubkey, "oca_pubkey_output.pem")) {
              logcat("successfully save OCA pubkey"
                      " in cert %s to oca_pubkey_output.pem\n",
                      external_oca_file);
            }
            else {
             logcat("fail to save OCA pubkey in cert %s to file\n", external_oca_file);
            }
        }
    }

    free(report_buf);
    return ret;
}
