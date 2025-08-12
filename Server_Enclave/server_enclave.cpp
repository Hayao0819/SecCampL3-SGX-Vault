#include <sgx_tseal.h>

#include <map>

#include "server_config.hpp"
#include "server_enclave_headers.hpp"
#include "server_enclave_ra.hpp"
#include "server_enclave_utils.hpp"
#include "sgx_error.h"

sgx_status_t ecall_sample_addition(uint32_t ra_ctx,
                                   uint8_t* cipher1, size_t cipher1_len, uint8_t* cipher2,
                                   size_t cipher2_len, uint8_t* iv, uint8_t* tag1,
                                   uint8_t* tag2, uint8_t* result, size_t* result_len,
                                   uint8_t* iv_result, uint8_t* tag_result) {
    sgx_status_t status = SGX_SUCCESS;
    sgx_ra_key_128_t sk_key, mk_key;

    memcpy(&sk_key, g_ra_sessions[ra_ctx].sk, 16);
    memcpy(&mk_key, g_ra_sessions[ra_ctx].mk, 16);

    if (cipher1_len > 32 || cipher2_len > 32) {
        const char* message = "The cipher size is too large.";
        ocall_print(message, 2);
        status = SGX_ERROR_INVALID_PARAMETER;
        return status;
    }

    /* GCMでは暗号文と平文の長さが同一 */
    uint8_t* plain_1 = new uint8_t[cipher1_len]();
    uint8_t* plain_2 = new uint8_t[cipher2_len]();

    /* GCM復号 */
    status = sgx_rijndael128GCM_decrypt(&sk_key, cipher1,
                                        cipher1_len, plain_1, iv, 12, NULL, 0,
                                        (sgx_aes_gcm_128bit_tag_t*)tag1);

    if (status != SGX_SUCCESS) {
        const char* message = "Failed to decrypt cipher1.";
        ocall_print(message, 2);  // 2はエラーログである事を表す
        ocall_print_status(status);
        return status;
    }

    status = sgx_rijndael128GCM_decrypt(&sk_key, cipher2,
                                        cipher2_len, plain_2, iv, 12, NULL, 0,
                                        (sgx_aes_gcm_128bit_tag_t*)tag2);

    if (status != SGX_SUCCESS) {
        const char* message = "Failed to decrypt cipher2.";
        ocall_print(message, 2);  // 2はエラーログである事を表す
        ocall_print_status(status);
        return status;
    }

    uint64_t num1 = atol((const char*)plain_1);
    uint64_t num2 = atol((const char*)plain_2);

    /* 加算を実行 */
    uint64_t total = num1 + num2;

    /* 返信用に暗号化を実施 */
    std::string total_str = std::to_string(total);
    uint8_t* total_u8 = (uint8_t*)total_str.c_str();

    *result_len = total_str.length();

    /* "32"はEnclave外で決め打ちで確保しているバッファ数 */
    if (*result_len > 32) {
        const char* message = "The result cipher size is too large.";
        ocall_print(message, 2);
        status = SGX_ERROR_INVALID_PARAMETER;
        return status;
    }

    /* RDRANDで真性乱数的にIVを生成 */
    status = sgx_read_rand(iv_result, 12);

    if (status != SGX_SUCCESS) {
        const char* message = "Failed to generate IV inside enclave.";
        ocall_print(message, 2);  // 2はエラーログである事を表す
        ocall_print_status(status);
        return status;
    }

    /* 計算結果をGCMで暗号化 */
    status = sgx_rijndael128GCM_encrypt(&mk_key,
                                        total_u8, *result_len, result, iv_result, 12,
                                        NULL, 0, (sgx_aes_gcm_128bit_tag_t*)tag_result);

    if (status != SGX_SUCCESS) {
        const char* message = "Failed to encrypt result.";
        ocall_print(message, 2);  // 2はエラーログである事を表す
        ocall_print_status(status);
        return status;
    }

    delete plain_1;
    delete plain_2;

    return status;
}

void ecall_init_app(uint8_t* app_config, size_t app_config_len) {
    ocall_print("Server Enclave initialized successfully.", 1);

    if (config == nullptr) {
        uint8_t unsealed_data_size = calc_unsealed_len(app_config, app_config_len);
        config = new SGXVaultConfig();
        config->user_data.clear();
        config->master_password.clear();
        uint8_t* unsealed_data = new uint8_t[unsealed_data_size]();

        if (app_config == nullptr || app_config_len <= 0) {
            ocall_print("App configuration data is null or empty.", 0);
            return;
        }

        int error_flag = 0;
        unsealing_bytes(app_config, app_config_len, unsealed_data, unsealed_data_size, &error_flag);

        // unsealed_dataをパースしてSGXVaultConfigに格納
        parse_unsealed_data(unsealed_data, unsealed_data_size, config);
        delete[] unsealed_data;

        if (error_flag != 0) {
            ocall_print("Failed to unseal the configuration data.", 2);
            delete config;
            config = nullptr;
            return;
        }
    }
    ocall_print("App configuration initialized.", 1);

    // return SGX_SUCCESS;
}

bool ecall_check_init_require() {
    return config == nullptr || config->master_password.empty();
}

sgx_status_t ecall_setup_master_password(const char* master_password) {
    if (config == nullptr) {
        config = new SGXVaultConfig();
    }

    if (config->master_password.size() > 0) {
        ocall_print("Master password is already set.", 2);
        return SGX_ERROR_UNEXPECTED;
    }

    sgx_sha256_hash_t password_hash;
    sgx_status_t password_hash_status = sgx_sha256_msg(
        reinterpret_cast<const uint8_t*>(master_password),
        strlen(master_password),
        &password_hash);
    if (password_hash_status != SGX_SUCCESS) {
        ocall_print("Failed to hash the master password.", 2);
        return password_hash_status;
    }
    config->master_password = std::string(reinterpret_cast<const char*>(password_hash), SGX_SHA256_HASH_SIZE);

    int ret = write_current_config();
    if (ret < 0) {
        ocall_print("Failed to write the current configuration.", 2);
        return SGX_ERROR_UNEXPECTED;
    }
    ocall_print("Master password set successfully.", 1);
    return SGX_SUCCESS;
}
