#include "headers.hpp"

/* Enclave内の値の出力を行うOCALL（主にデバッグやログ用） */
void ocall_print(const char* str, int log_type) {
    MESSAGE_TYPE type;
    if (log_type == 0)
        type = DEBUG_LOG;
    else if (log_type == 1)
        type = INFO;
    else
        type = ERROR;

    print_debug_message("OCALL output-> ", type);
    print_debug_message(str, type);

    return;
}

/* SGXステータスを識別し具体的な内容表示する */
void ocall_print_status(sgx_status_t st) {
    print_sgx_status(st);
    return;
}

/* バイナリを標準出力する確認用関数 */
void ocall_print_binary(uint8_t* buf, size_t sz) {
    BIO_dump_fp(stdout, (char*)buf, sz);
    return;
}

