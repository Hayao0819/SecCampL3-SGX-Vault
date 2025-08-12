#include "headers.hpp"
#include "server_sgx.hpp"

int main() {
    print_debug_message("", INFO);
    print_debug_message("Launched ISV's untrusted application.", INFO);

    /* Azure上でのDCAP-RAでは、プロセス外で動作するAEを使用するout-of-procモードが
     * 推奨されているため、out-of-procモードを前提とする */
    bool is_out_of_proc = false;
    char* out_of_proc = std::getenv("SGX_AESM_ADDR");

    if (!out_of_proc) {
        std::string message = "Only out-of-proc mode is supported. ";
        message += "Check your machine's configuration.";
        print_debug_message(message, ERROR);

        return -1;
    }

    sgx_enclave_id_t eid = -1;

    /* Enclaveの初期化 */
    if (initialize_enclave(eid) < 0) {
        std::string message = "Failed to initialize Enclave.";
        print_debug_message(message, ERROR);

        return -1;
    }

    /* サーバの起動（RAの実行） */
    std::thread srvthread(server_logics, eid);

    /* サーバ停止準備。実際の停止処理は後ほど実装 */
    srvthread.join();
}
