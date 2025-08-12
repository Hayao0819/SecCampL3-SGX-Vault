
#include "headers.hpp"
#include "server_ra.hpp"

/* settingsファイルからロードした値を格納する構造体 */
typedef struct server_settings_struct {
    std::string pce_path;
    std::string qe3_path;
    std::string ide_path;
    std::string qpl_path;
} settings_t;

settings_t g_settings;
/* SPから受信した2値をEnclave内で復号し加算して結果を返却 */
int sample_addition(sgx_enclave_id_t eid, std::string request_json,
                    std::string& response_json, std::string error_message) {
    print_debug_message("==============================================", INFO);
    print_debug_message("Sample Addition", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    json::JSON req_json_obj = json::JSON::Load(request_json);

    uint8_t *cipher1, *cipher2;
    uint8_t *iv, *tag1, *tag2;
    size_t cipher1_len, cipher2_len, tmpsz;
    uint32_t ra_ctx;

    // RAのセッション識別ID
    ra_ctx = std::stoi(base64_decode<char, char>((char*)req_json_obj["ra_context"].ToString().c_str(), tmpsz));

    //
    cipher1 = base64_decode<uint8_t, char>((char*)req_json_obj["cipher1"].ToString().c_str(), cipher1_len);
    cipher2 = base64_decode<uint8_t, char>((char*)req_json_obj["cipher2"].ToString().c_str(), cipher2_len);

    // 初期化ベクトル
    iv = base64_decode<uint8_t, char>((char*)req_json_obj["iv"].ToString().c_str(), tmpsz);

    // 各cipherのタグ
    tag1 = base64_decode<uint8_t, char>((char*)req_json_obj["tag1"].ToString().c_str(), tmpsz);
    tag2 = base64_decode<uint8_t, char>((char*)req_json_obj["tag2"].ToString().c_str(), tmpsz);

    sgx_status_t status, retval;
    uint8_t *result, *iv_result, *tag_result;
    size_t result_len;

    iv_result = new uint8_t[12]();
    tag_result = new uint8_t[16]();

    /* 結果用バッファサイズは決め打ち。uint64_t同士の加算であるため、
     * 本来は10バイトもあれば十分である。
     * 行儀よくやるのであれば、サイズ把握用の関数を用意するのが良いが、
     * 事実上二重処理になるため、行う処理の重さと相談する */
    result = new uint8_t[32]();

    /* ECALLを行い秘密計算による加算を実行 */
    print_debug_message("Invoke ECALL for addition.", DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    status = ecall_sample_addition(eid, &retval, ra_ctx, cipher1,
                                   cipher1_len, cipher2, cipher2_len, iv, tag1, tag2,
                                   result, &result_len, iv_result, tag_result);

    if (status != SGX_SUCCESS) {
        error_message = "Failed to complete sample addition ECALL.";
        return -1;
    }

    json::JSON res_json_obj;

    res_json_obj["cipher"] = std::string(
        base64_encode<char, uint8_t>(result, result_len));

    res_json_obj["iv"] = std::string(
        base64_encode<char, uint8_t>(iv_result, 12));

    res_json_obj["tag"] = std::string(
        base64_encode<char, uint8_t>(tag_result, 16));

    response_json = res_json_obj.dump();

    return 0;
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

void handler_sample_addition(sgx_enclave_id_t eid, const Request& req, Response& res) {
    std::string request_json = req.body;
    std::string response_json, error_message = "";
    int ret = sample_addition(eid, request_json, response_json, error_message);
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
    res.status = 200;
    res.set_content(status_json.dump(), "application/json");
}

void handler_set_password(sgx_enclave_id_t eid, const Request& req, Response& res) {
    std::string master_password = req.body;
    sgx_status_t setup_master_password_status;
    sgx_status_t status = ecall_setup_master_password(eid, &setup_master_password_status, master_password.c_str());
    print_sgx_status(status);
    if (status != SGX_SUCCESS) {
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
