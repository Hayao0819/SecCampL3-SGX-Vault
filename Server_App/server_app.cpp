#include "headers.hpp"
#include "server_sgx.hpp"

uint8_t* load_config_file(const char* config_file_path, long& config_size) {
    if (!config_file_path) {
        std::string message = "Configuration file is not specified.";
        print_debug_message(message, ERROR);
        return nullptr;
    }
    FILE* config_file = fopen(config_file_path, "r");
    if (!config_file) {
        // ファイルが存在しない場合は空ファイルを作成
        config_file = fopen(config_file_path, "w+");
        if (!config_file) {
            std::string message = "Failed to create empty configuration file: ";
            message += config_file_path;
            print_debug_message(message, ERROR);
            return nullptr;
        }
    }
    fseek(config_file, 0, SEEK_END);
    config_size = ftell(config_file);
    fseek(config_file, 0, SEEK_SET);

    uint8_t* config_data = nullptr;
    if (config_size > 0) {
        config_data = new uint8_t[config_size];
        size_t read_size = fread(config_data, 1, config_size, config_file);
        if (read_size != config_size) {
            std::string message = "Failed to read configuration file completely.";
            print_debug_message(message, ERROR);
            delete[] config_data;
            fclose(config_file);
            return nullptr;
        }
    } else {
        // 空ファイルの場合は空バッファを返す
        config_data = new uint8_t[0];
        config_size = 0;
    }
    fclose(config_file);
    return config_data;
}

int main(int argc, char* argv[]) {
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

    /* 設定ファイル読み込みとアプリの初期化*/
    long config_size = 0;
    uint8_t* config_data = load_config_file("./sever-data.dat", config_size);
    if (!config_data) {
        return -1;
    }
    ecall_init_app(eid, config_data, config_size);

    /* サーバの起動（RAの実行） */
    std::thread srvthread(server_logics, eid);

    /* サーバ停止準備。実際の停止処理は後ほど実装 */
    srvthread.join();
    delete[] config_data;
}
