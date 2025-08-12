
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

// 各エンドポイントのハンドラ関数宣言
void handler_init_ra(sgx_enclave_id_t eid, const Request& req, Response& res);
void handler_get_quote(sgx_enclave_id_t eid, const Request& req, Response& res);
void handler_ra_result(sgx_enclave_id_t eid, const Request& req, Response& res);
void handler_sample_addition(sgx_enclave_id_t eid, const Request& req, Response& res);
void handler_destruct_ra(sgx_enclave_id_t eid, const Request& req, Response& res);
void handler_hi(const Request& req, Response& res);
void handler_stop(sgx_enclave_id_t eid, Server& svr, const Request& req, Response& res);
void handler_status(sgx_enclave_id_t eid, const Request& req, Response& res);
void handler_set_password(sgx_enclave_id_t eid, const Request& req, Response& res);
