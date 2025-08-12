#include <sgx_attributes.h>
#include <sgx_trts.h>
#include <sgx_tseal.h>
#include <string.h>

#include "server_enclave_headers.hpp"
#define MRENCLAVE 0
#define MRSIGNER 1

// template <typename T>
// std::vector<uint8_t> sealing_data(const T& obj, int policy) {
//     const uint8_t* message = reinterpret_cast<const uint8_t*>(&obj);
//     int message_len = sizeof(T);
//     // SGXのsealedデータサイズ計算
//     uint32_t sealed_len = sgx_calc_sealed_data_size(0, message_len);
//     std::vector<uint8_t> sealed(sealed_len);
//     sealing_bytes(const_cast<uint8_t*>(message), message_len, sealed.data(), sealed_len, policy);
//     return sealed;
// }

void sealing_bytes(uint8_t* message, int message_len, uint8_t* sealed, int sealed_len, int policy) {
    uint16_t key_policy;
    sgx_status_t status;
    sgx_attributes_t attr;
    sgx_misc_select_t misc = 0xF0000000;

    attr.flags = 0xFF0000000000000B;
    attr.xfrm = 0;

    if (policy == MRENCLAVE) {
        key_policy = 0x0001;
    } else {
        key_policy = 0x0002;
    }

    status = sgx_seal_data_ex(key_policy, attr, misc, 0, NULL,
                              message_len, message, sealed_len, (sgx_sealed_data_t*)sealed);

    ocall_print_status(status);
}

void unsealing_bytes(uint8_t* sealed, int sealed_len,
                     uint8_t* unsealed, int unsealed_len, int* error_flag) {
    sgx_status_t status;

    status = sgx_unseal_data((sgx_sealed_data_t*)sealed, NULL, 0,
                             unsealed, (uint32_t*)&unsealed_len);

    ocall_print_status(status);

    if (status != SGX_SUCCESS) {
        *error_flag = 0xDEADBEEF;
    }
}

int calc_unsealed_len(uint8_t* sealed, int sealed_len) {
    return sgx_get_encrypt_txt_len((sgx_sealed_data_t*)sealed);
}
