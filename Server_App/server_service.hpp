#pragma once
#include "headers.hpp"

// settingsファイルからロードした値を格納する構造体
typedef struct server_settings_struct {
    std::string pce_path;
    std::string qe3_path;
    std::string ide_path;
    std::string qpl_path;
} settings_t;

extern settings_t g_settings;

// SPから受信した2値をEnclave内で復号し加算して結果を返却
int sample_addition(sgx_enclave_id_t eid, std::string request_json,
                    std::string& response_json, std::string error_message);
