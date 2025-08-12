#include "headers.hpp"

/* Enclaveの初期化 */
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
        print_sgx_status(status);
        return -1;
    }

    return 0;
}
