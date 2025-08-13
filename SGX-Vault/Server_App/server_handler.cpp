
#include "headers.hpp"
#include "server_ra.hpp"
#include "server_service.hpp"

/* settingsファイルからロードした値を格納する構造体 */
typedef struct server_settings_struct {
    std::string pce_path;
    std::string qe3_path;
    std::string ide_path;
    std::string qpl_path;
} settings_t;

settings_t g_settings;

bool middleware_master_key(sgx_enclave_id_t eid, std::string input_key) {
    // ここにマスターパスワードのミドルウェア処理を実装
    // 例えば、入力されたキーがマスターパスワードと一致するか確認するなど
    print_debug_message("Middleware for master key processing.", INFO);

    bool authenticated = false;

    ecall_authenticate_master_password(eid, &authenticated, input_key.c_str());
    return authenticated;
}

// 各エンドポイントのハンドラ関数
void handler_init_ra(sgx_enclave_id_t eid, const Request& req, Response& res) {
    std::string response_json, error_message = "";
    std::string request_json = req.body;
    int ret = initialize_ra(eid, request_json, response_json, error_message);
    if (!ret)
        res.status = 200;
    else {
        char* error_message_b64;
        error_message_b64 = base64_encode<char, char>((char*)error_message.c_str(), error_message.length());
        json::JSON json_obj;
        json_obj["error_message"] = std::string(error_message_b64);
        response_json = json_obj.dump();
        res.status = 500;
    }
    res.set_content(response_json, "application/json");
}

void handler_get_quote(sgx_enclave_id_t eid, const Request& req, Response& res) {
    std::string request_json = req.body;
    std::string response_json, error_message = "";
    int ret = get_quote(eid, request_json, response_json, error_message);
    print_debug_message("Quote JSON ->", DEBUG_LOG);
    print_debug_message(response_json, DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);
    if (!ret)
        res.status = 200;
    else {
        char* error_message_b64;
        error_message_b64 = base64_encode<char, char>((char*)error_message.c_str(), error_message.length());
        json::JSON json_obj;
        json_obj["error_message"] = std::string(error_message_b64);
        response_json = json_obj.dump();
        res.status = 500;
    }
    res.set_content(response_json, "application/json");
}

void handler_ra_result(sgx_enclave_id_t eid, const Request& req, Response& res) {
    std::string request_json = req.body;
    std::string response_json, error_message = "";
    int ret = process_ra_result(eid, request_json, response_json, error_message);
    if (!ret)
        res.status = 200;
    else {
        char* error_message_b64;
        error_message_b64 = base64_encode<char, char>((char*)error_message.c_str(), error_message.length());
        json::JSON json_obj;
        json_obj["error_message"] = std::string(error_message_b64);
        response_json = json_obj.dump();
        res.status = 500;
    }
    res.set_content(response_json, "application/json");
}

void handler_destruct_ra(sgx_enclave_id_t eid, const Request& req, Response& res) {
    std::string request_json = req.body;
    std::string response_json, error_message = "";
    destruct_ra_context(eid, request_json);
    res.status = 200;
    json::JSON res_json_obj;
    res_json_obj["message"] = std::string("OK");
    response_json = res_json_obj.dump();
    res.set_content(response_json, "application/json");
}

void handler_hi(const Request& req, Response& res) {
    res.set_content("Hello World!", "text/plain");
}

void handler_stop(sgx_enclave_id_t eid, Server& svr, const Request& req, Response& res) {
    sgx_destroy_enclave(eid);
    svr.stop();
}

void handler_status(sgx_enclave_id_t eid, const Request& req, Response& res) {
    json::JSON status_json;

    bool init_require = false;
    ecall_check_init_require(eid, &init_require);
    status_json["init_require"] = init_require;

    int stored_pass_count = 0;
    ecall_stored_stat(eid, &stored_pass_count);
    status_json["stored_password_count"] = stored_pass_count;

    res.status = 200;
    res.set_content(status_json.dump(), "application/json");
}

void handler_set_masterkey(sgx_enclave_id_t eid, const Request& req, Response& res) {
    std::string master_password = req.body;
    sgx_status_t setup_master_password_status;
    sgx_status_t status = ecall_setup_master_password(eid, &setup_master_password_status, master_password.c_str());
    if (setup_master_password_status != SGX_SUCCESS) {
        res.status = 500;
        json::JSON res_json_obj;
        res_json_obj["error_message"] = "Failed to set master password.";
        res.set_content(res_json_obj.dump(), "application/json");
        return;
    }
    res.status = 200;
    json::JSON res_json_obj;
    res_json_obj["message"] = "Master password set successfully.";
    res.set_content(res_json_obj.dump(), "application/json");
}

void handler_store_password(sgx_enclave_id_t eid, const Request& req, Response& res) {
    std::string master_key = req.get_param_value("master_key");
    std::string key = req.get_param_value("key");
    std::string value = req.get_param_value("value");

    bool authorized = middleware_master_key(eid, master_key);
    if (!authorized) {
        res.status = 403;
        json::JSON res_json_obj;
        res_json_obj["error_message"] = "Unauthorized access. Invalid master key.";
        res.set_content(res_json_obj.dump(), "application/json");
        return;
    }

    sgx_status_t store_password_result;
    sgx_status_t status = ecall_store_password(eid, &store_password_result, key.c_str(), value.c_str());
    if (status != SGX_SUCCESS) {
        res.status = 500;
        json::JSON res_json_obj;
        res_json_obj["error_message"] = "Failed to store password.";
        res.set_content(res_json_obj.dump(), "application/json");
        return;
    }

    res.status = 200;
    json::JSON res_json_obj;
    res_json_obj["message"] = "Password stored successfully.";
    res.set_content(res_json_obj.dump(), "application/json");
}
void handler_get_password(sgx_enclave_id_t eid, const Request& req, Response& res) {
    std::string master_key = req.get_param_value("master_key");
    std::string key = req.get_param_value("key");

    // 認証チェック
    bool authorized = middleware_master_key(eid, master_key);
    if (!authorized) {
        res.status = 403;
        json::JSON res_json_obj;
        res_json_obj["error_message"] = "Unauthorized access. Invalid master key.";
        res.set_content(res_json_obj.dump(), "application/json");
        return;
    }

    // パスワード長を取得（ヌル終端込み）
    size_t value_len = 0;
    sgx_status_t get_password_length_status;
    ecall_get_password_length(eid, &get_password_length_status, key.c_str(), &value_len);

    if (get_password_length_status != SGX_SUCCESS || value_len == 0) {
        res.status = 404;
        json::JSON res_json_obj;
        res_json_obj["error_message"] = "Key not found or password length is zero.";
        res.set_content(res_json_obj.dump(), "application/json");
        return;
    }

    // バッファ確保（返ってきた値が終端込みなのでそのまま確保）
    char* value = new char[value_len];
    memset(value, 0, value_len);

    // パスワード取得
    sgx_status_t get_password_status;
    sgx_status_t status = ecall_get_password(eid, &get_password_status, key.c_str(), value, value_len);

    if (status != SGX_SUCCESS || get_password_status != SGX_SUCCESS) {
        delete[] value;
        res.status = 500;
        json::JSON res_json_obj;
        print_sgx_status(status);
        print_sgx_status(get_password_status);
        res_json_obj["error_message"] = "Failed to retrieve password.";
        res.set_content(res_json_obj.dump(), "application/json");
        return;
    }

    // 正常レスポンス
    print_debug_message("Retrieved password for key: " + key, INFO);

    json::JSON res_json_obj;
    res_json_obj["key"] = key;
    res_json_obj["value"] = std::string(value);  // ヌル終端が保証されているのでOK

    delete[] value;

    res.status = 200;
    res.set_content(res_json_obj.dump(), "application/json");
}

void handler_encrypt_sample_addition(sgx_enclave_id_t eid, const Request& req, Response& res) {
    std::string request_json = req.body;
    std::string response_json, error_message = "";
    int ret = encrypt_sample_addition(eid, request_json, response_json, error_message);
    if (!ret)
        res.status = 200;
    else {
        json::JSON res_json_obj;
        char* error_message_b64;
        error_message_b64 = base64_encode<char, char>((char*)error_message.c_str(), error_message.length());
        res_json_obj["error_message"] = std::string(error_message_b64);
        response_json = res_json_obj.dump();
        res.status = 500;
    }
    print_debug_message("send the result response to SP.", INFO);
    print_debug_message("", INFO);
    res.set_content(response_json, "application/json");
}
