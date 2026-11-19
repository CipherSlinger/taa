---
title: "HCT附录"
docCode: "2021829718207414272"
updated: "2026-08-13 16:21:40"
breadcrumb: "C86 DevKit / 03. 密码技术 / 02. 用户指南 / HCT-3.x 指南 / HCT附录"
source: https://c86.sourcefind.cn/documents/2/2021829718207414272
---
# 开源社区QEMU PR列表

## 龙蜥社区qemu-8.2 PR列表

|PR|备注|
|:-|:-|
|https://gitee.com/src-anolis-os/qemu/pulls/33 |CAE基础patch(龙蜥老仓库)|
|https://gitee.com/anolis/qemu-kvm/pulls/69<br>https://gitee.com/anolis/qemu-kvm/pulls/73|CAE，热迁移|
|https://gitee.com/src-anolis-os/qemu/pulls/16| TKM基础patch (龙蜥老仓库)|
|https://gitee.com/anolis/qemu-kvm/pulls/26|TKM支持在CSV虚拟机中使用|
|https://gitee.com/anolis/qemu-kvm/pulls/70|TKM热迁移|

## 龙蜥社区qemu-6.2 PR列表

|PR|备注|
|:-|:-|
|https://gitee.com/src-anolis-os/qemu-kvm/pulls/67|CAE基础patch|
|https://gitee.com/src-anolis-os/qemu-kvm/pulls/74|CAE，热迁移|
|https://gitee.com/src-anolis-os/qemu-kvm/pulls/51|TKM基础patch|
|https://gitee.com/src-anolis-os/qemu-kvm/pulls/65|TKM支持在CSV虚拟机中使用|
|https://gitee.com/src-anolis-os/qemu-kvm/pulls/73|TKM热迁移|

# CAE热迁移Demo用例

```
/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 HYGON Corporation . All rights reserved.
 */

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#define SM4_BLOCK_SIZE 16
static ENGINE *e = NULL;

/**
 * @brief do SM4-ECB by engine and set the result to arg ciphertext
 * @return success on 1, fail on 0
 */
static int do_sm4_ccp_ecb(const uint8_t *input, uint32_t ilen,
                          const uint8_t *key, uint8_t *output, int enc)
{
    EVP_CIPHER_CTX *evp_cipher_ctx = NULL;
    int tmplen;
    int ok = 0;

    evp_cipher_ctx = EVP_CIPHER_CTX_new();
    if (!evp_cipher_ctx)
    {
        ok = -1;
        goto done;
    }

    if (!EVP_CipherInit_ex(evp_cipher_ctx, EVP_sm4_ecb(), e, key, NULL, enc))
    {
        ok = -1;
        goto done;
    }

    EVP_CIPHER_CTX_set_padding(evp_cipher_ctx, 0);

    /* Use VFIO CCP Encrypt plaintext message */
    if (!EVP_CipherUpdate(evp_cipher_ctx, output, &tmplen, input, ilen))
    {
        ok = -1;
        goto done;
    }

    if(!EVP_CipherFinal_ex(evp_cipher_ctx, output + tmplen, &tmplen))
    {
        ok = -1;
        goto done;
    }

done:
    EVP_CIPHER_CTX_free(evp_cipher_ctx);
    return ok;
}


#define TEST_LEN (64 * 1024)
void run_loop(uint32_t loop_cnt)
{
    uint8_t *data = NULL;
    uint8_t *input, *penc, *pdec;
    uint32_t ilen;
    static const uint8_t k[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    data = malloc(3 * TEST_LEN);
    if (data == NULL)
    {
        printf("[%s]:%d, malloc error.\n", __func__, __LINE__);
        goto done;
    }

    input = data;
    penc = input + TEST_LEN;
    pdec = penc + TEST_LEN;
    ilen = TEST_LEN;

    while(loop_cnt--)
    {
        printf("loop_cnt = %d\n", loop_cnt);
        // encypt
        if (0 != do_sm4_ccp_ecb(input, ilen, k, penc, 1))
        {
            printf("[%s]:%d, do_sm4_ccp_ecb error.\n", __func__, __LINE__);
            break;
        }
        // decrypt
        if (0 != do_sm4_ccp_ecb(penc, ilen, k, pdec, 0))
        {
            printf("[%s]:%d, do_sm4_ccp_ecb error.\n", __func__, __LINE__);
            break;
        }

        if (memcmp(input, pdec, ilen))
        {
            printf("[%s]:%d, result check failed.\n", __func__, __LINE__);
            break;
        }
        sleep(1);
    }

done:
    if (data)
    {
        free(data);
    }
}

int main(void)
{
    ENGINE_load_builtin_engines();
    e = ENGINE_by_id("hct");
    if (e == NULL)
    {
        printf("[%s]:%d, load engine failed.\n", __func__, __LINE__);
        goto done;
    }

    run_loop(100);
done:
    ENGINE_free(e);
    return 0;
}
```
