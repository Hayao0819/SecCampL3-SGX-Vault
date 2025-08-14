#include <sgx_urts.h>
#include <sgx_uswitchless.h>

#include <cstdio>
#include <cstring>
#include <iostream>

#include "Enclave_u.h"
#include "error_print.h"

sgx_enclave_id_t global_eid = 0;

/* OCALL implementations */
void ocall_print(const char* str) {
    std::cout << "Output from OCALL: " << std::endl;
    std::cout << str << std::endl;

    return;
}

/* Enclave initialization function */
int initialize_enclave(sgx_enclave_id_t& eid) {
    /* LEはDeprecatedになったので、起動トークンはダミーで代用する */
    sgx_launch_token_t token = {0};

    /* 起動トークンが更新されているかのフラグ。Deprecated。 */
    int updated = 0;

    /* 署名済みEnclaveイメージファイル名 */
    std::string enclave_image_name = "enclave.signed.so";

    sgx_status_t status;

    sgx_uswitchless_config_t us_config = SGX_USWITCHLESS_CONFIG_INITIALIZER;
    void* enclave_ex_p[32] = {0};

    enclave_ex_p[SGX_CREATE_ENCLAVE_EX_SWITCHLESS_BIT_IDX] = &us_config;

    /*
     * Switchless Callが有効化されたEnclaveの作成。
     * NULLの部分はEnclaveの属性（sgx_misc_attribute_t）が入る部分であるが、
     * 不要かつ省略可能なのでNULLで省略している。
     */
    status = sgx_create_enclave_ex(enclave_image_name.c_str(), SGX_DEBUG_FLAG,
                                   &token, &updated, &eid, NULL, SGX_CREATE_ENCLAVE_EX_SWITCHLESS,
                                   (const void**)enclave_ex_p);

    if (status != SGX_SUCCESS) {
        /* error_print.cppで定義 */
        sgx_error_print(status);
        return -1;
    }

    return 0;
}

int main_logic() {
    sgx_status_t status = ecall_test(global_eid, &retval,
                                     message, message_len);

    if (status != SGX_SUCCESS) {
        sgx_error_print(status);

        return -1;
    } else {
        /* This function also can display succeeded message */
        sgx_error_print(status);
    }
}

int main() {
    sgx_enclave_id_t eid = -1;

    /* initialize enclave */
    if (initialize_enclave(eid) < 0) {
        std::cerr << "App: fatal error: Failed to initialize enclave.";
        std::cerr << std::endl;
        return -1;
    }

    /* start ECALL */
    const char* message = "Hello Enclave.";
    size_t message_len = strlen(message);
    int retval = -9999;

    std::cout << "Execute ECALL.\n"
              << std::endl;

    main_logic();

    /* print ECALL result */
    std::cout << "\nReturned integer from ECALL is: " << retval << std::endl;
    std::cout << std::endl;

    /* Destruct the enclave */
    sgx_destroy_enclave(global_eid);

    std::cout << "Whole operations have been executed correctly." << std::endl;

    return 0;
}
