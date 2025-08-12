#include "headers.hpp"

/* sgx_ra_context_t相当のRAセッション識別子の初期化を行う */
int initialize_ra(sgx_enclave_id_t eid, std::string request_json,
                  std::string& response_json, std::string& error_message) {
    uint32_t ra_ctx = -1;  // EPID-RAのsgx_ra_context_t相当
    sgx_status_t status, retval;

    print_debug_message("", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("Initialize RA", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    json::JSON req_json_obj = json::JSON::Load(request_json);
    uint32_t client_id = -1;
    size_t tmpsz;

    /* Client ID（署名検証鍵インデックス）のパース */
    std::string client_id_b64 = std::string(base64_decode<char, char>(
        (char*)req_json_obj["client_id"].ToString().c_str(), tmpsz));

    try {
        client_id = std::stoi(client_id_b64);
    } catch (...) {
        error_message = "Invalid client ID format.";
        print_debug_message(error_message, ERROR);
        print_debug_message("", ERROR);

        return -1;
    }

    /* クライアントに返すセッション公開鍵のガワの準備 */
    sgx_ec256_public_t Ga;

    if (SGX_ECP256_KEY_SIZE != 32) {
        error_message = "Internal key size error.";
        print_debug_message(error_message, ERROR);
        print_debug_message("", ERROR);

        return -1;
    }

    memset(&Ga.gx, 0, SGX_ECP256_KEY_SIZE);
    memset(&Ga.gy, 0, SGX_ECP256_KEY_SIZE);

    status = ecall_init_ra(eid, &retval, client_id, &ra_ctx, &Ga);

    if (status != SGX_SUCCESS) {
        error_message = "Failed to initialize RA.";
        print_sgx_status(status);
        print_debug_message(error_message, ERROR);
        print_debug_message("", ERROR);

        return -1;
    }

    print_debug_binary("Server's session pubkey G_a",
                       (uint8_t*)&Ga, sizeof(Ga), DEBUG_LOG);

    print_debug_binary("x-coordinate of G_a", Ga.gx, 32, DEBUG_LOG);
    print_debug_binary("y-coordinate of G_a", Ga.gy, 32, DEBUG_LOG);

    std::string ra_ctx_str;
    char* ra_ctx_b64;

    ra_ctx_str = std::to_string(ra_ctx);
    ra_ctx_b64 = base64_encode<char, char>(
        (char*)ra_ctx_str.c_str(), ra_ctx_str.length());

    /* レスポンス用JSONの作成 */
    json::JSON res_json_obj;
    res_json_obj["ra_context"] = std::string(ra_ctx_b64);
    res_json_obj["g_a"]["gx"] =
        std::string((char*)base64_encode<char, uint8_t>(Ga.gx, 32));
    res_json_obj["g_a"]["gy"] =
        std::string((char*)base64_encode<char, uint8_t>(Ga.gy, 32));

    print_debug_message("Base64-encoded x-coordinate of Ga ->", DEBUG_LOG);
    print_debug_message(res_json_obj["g_a"]["gx"].ToString(), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    print_debug_message("Base64-encoded y-coordinate of Ga ->", DEBUG_LOG);
    print_debug_message(res_json_obj["g_a"]["gy"].ToString(), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    response_json = res_json_obj.dump();

    return 0;
}

/* Quoteの素材とする、ServerのEnclaveのReport構造体の取得 */
int get_server_enclave_report(sgx_enclave_id_t eid, uint32_t ra_ctx,
                              sgx_target_info_t qe3_target_info, sgx_report_t& report) {
    sgx_status_t status, retval;

    status = ecall_create_report(eid, &retval,
                                 ra_ctx, &qe3_target_info, &report);

    if (status != SGX_SUCCESS) {
        print_sgx_status(status);
        std::string message = "Failed to ecall.";
        print_debug_message(message, ERROR);

        return -1;
    }

    if (retval != SGX_SUCCESS) {
        print_sgx_status(status);
        std::string message = "Failed to create REPORT.";
        print_debug_message(message, ERROR);

        return -1;
    }

    return 0;
}

/* セッションキーの処理をしQuoteを取得 */
int get_quote(sgx_enclave_id_t eid, std::string request_json,
              std::string& response_json, std::string& error_message) {
    print_debug_message("==============================================", INFO);
    print_debug_message("Generate and validate session keys", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    json::JSON req_json_obj = json::JSON::Load(request_json);
    size_t tmpsz;

    std::string ra_ctx_str = std::string(base64_decode<char, char>(
        (char*)req_json_obj["ra_context"].ToString().c_str(), tmpsz));

    uint32_t ra_ctx;

    try {
        ra_ctx = std::stoi(ra_ctx_str);
    } catch (...) {
        print_debug_message("Invalid RA context format.", ERROR);
        return -1;
    }

    std::string client_id_str = std::string(base64_decode<char, char>(
        (char*)req_json_obj["client_id"].ToString().c_str(), tmpsz));

    uint32_t client_id;

    try {
        client_id = std::stoi(client_id_str);
    } catch (...) {
        print_debug_message("Invalid RA context format.", ERROR);
        return -1;
    }

    sgx_ec256_public_t Gb;
    sgx_ec256_signature_t sigsp;

    /* クライアントの公開鍵Gb */
    memcpy(Gb.gx, base64_decode<uint8_t, char>((char*)req_json_obj["g_b"]["gx"].ToString().c_str(), tmpsz), 32);
    memcpy(Gb.gy, base64_decode<uint8_t, char>((char*)req_json_obj["g_b"]["gy"].ToString().c_str(), tmpsz), 32);

    /* Gb_Gaに対するECDSA署名であるSigSP */
    memcpy(sigsp.x, base64_decode<uint8_t, char>((char*)req_json_obj["sigsp"]["x"].ToString().c_str(), tmpsz), 32);
    memcpy(sigsp.y, base64_decode<uint8_t, char>((char*)req_json_obj["sigsp"]["y"].ToString().c_str(), tmpsz), 32);

    sgx_status_t status, retval;

    /* 交換した公開鍵の署名を検証し共通鍵生成 */
    status = ecall_process_session_keys(eid, &retval, ra_ctx, client_id, &Gb, &sigsp);

    if (status != SGX_SUCCESS) {
        print_sgx_status(status);
        error_message = "Failed to generate shared keys.";
        print_debug_message(error_message, ERROR);

        return -1;
    }

    if (retval != SGX_SUCCESS) {
        print_sgx_status(retval);
        error_message = "Failed to generate shared keys.";
        print_debug_message(error_message, ERROR);

        return -1;
    }

    print_debug_message("==============================================", INFO);
    print_debug_message("Get Quote", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    sgx_target_info_t qe3_target_info;
    quote3_error_t qe3_error;

    /* RAの一環であるQE3とのLAのため、QE3のTarget Infoを取得する */
    qe3_error = sgx_qe_get_target_info(&qe3_target_info);
    ;

    if (qe3_error != SGX_QL_SUCCESS) {
        print_ql_status(qe3_error);
        error_message = "Failed to get QE3's target info.";
        print_debug_message(error_message, ERROR);

        return -1;
    }

    print_debug_binary("QE3's target info", (uint8_t*)&qe3_target_info,
                       sizeof(sgx_target_info_t), DEBUG_LOG);

    /* ServerのEnclaveのREPORT構造体を取得 */
    sgx_report_t report = {0};
    memset(&report, 0, sizeof(sgx_report_t));

    int ret = get_server_enclave_report(eid, ra_ctx, qe3_target_info, report);

    if (ret) return -1;

    print_debug_binary("Server Enclave's Report", (uint8_t*)&report,
                       sizeof(sgx_report_t), DEBUG_LOG);

    /* 取得するQuoteのサイズを算出し、そのサイズ数を取得する */
    uint32_t quote_size = 0;
    qe3_error = sgx_qe_get_quote_size(&quote_size);

    if (qe3_error != SGX_QL_SUCCESS) {
        print_ql_status(qe3_error);
        std::string message = "Failed to get Quote size.";
        print_debug_message(message, ERROR);
        print_debug_message("", ERROR);

        return -1;
    }

    print_debug_message("Quote size ->", DEBUG_LOG);
    print_debug_message(std::to_string(quote_size), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    /* Quoteを取得する */
    uint8_t* quote_u8 = new uint8_t[quote_size]();

    qe3_error = sgx_qe_get_quote(&report, quote_size, quote_u8);

    if (qe3_error != SGX_QL_SUCCESS) {
        print_ql_status(qe3_error);
        std::string message = "Failed to get Quote.";
        print_debug_message(message, ERROR);
        print_debug_message("", ERROR);

        return -1;
    }

    print_debug_binary("Server Enclave's Quote",
                       quote_u8, quote_size, DEBUG_LOG);

    /* 値のチェック */
    sgx_quote3_t* quote = (sgx_quote3_t*)quote_u8;
    sgx_ql_auth_data_t* auth_data = NULL;
    sgx_ql_ecdsa_sig_data_t* sig_data = NULL;
    sgx_ql_certification_data_t* cert_data = NULL;

    sig_data = (sgx_ql_ecdsa_sig_data_t*)quote->signature_data;
    auth_data = (sgx_ql_auth_data_t*)sig_data->auth_certification_data;
    cert_data = (sgx_ql_certification_data_t*)((uint8_t*)auth_data + sizeof(*auth_data) + auth_data->size);

    print_debug_message("cert key type ->", DEBUG_LOG);
    print_debug_message(std::to_string(cert_data->cert_key_type), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    /* Report Dataの上位32bitには、完全性を維持したいデータのハッシュが入っている */
    print_debug_binary("first 32 bytes of report data",
                       quote->report_body.report_data.d, 32, DEBUG_LOG);

    // ダミー変数。この部分はクライアント側で置換する
    int content_size = 32;
    uint8_t* report_data_content = new uint8_t[content_size]();

    /* レスポンスの生成 */
    std::string quote_b64 = std::string(
        base64url_encode<char, uint8_t>(quote_u8, quote_size));
    std::string report_data_b64 = std::string(
        base64url_encode<char, uint8_t>(report_data_content, content_size));

    /* MAAがURLセーフBase64を受理しているため、その変換を行う */
    print_debug_message("URL-safe-Base64 encoded quote ->", DEBUG_LOG);
    print_debug_message(quote_b64, DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    /* Report Dataの上位32ビット（つまりコンテンツのハッシュ値）を渡すのではなく、
     * ハッシュ値に対応する元データの方を渡す点に注意 */
    print_debug_message(
        "URL-safe-Base64 encoded report data content ->", DEBUG_LOG);
    print_debug_message(report_data_b64, DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    json::JSON res_json_obj;

    res_json_obj["quote"] = quote_b64;
    res_json_obj["runtimeData"]["data"] = report_data_b64;
    res_json_obj["runtimeData"]["dataType"] = "Binary";
    response_json = res_json_obj.dump();

    memset(quote_u8, 0, quote_size);
    delete[] quote_u8;

    return 0;
}

/* RA結果の処理 */
int process_ra_result(sgx_enclave_id_t eid, std::string request_json,
                      std::string& response_json, std::string& error_message) {
    print_debug_message("==============================================", INFO);
    print_debug_message("Process RA result", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    json::JSON res_json_obj;
    json::JSON req_json_obj = json::JSON::Load(request_json);

    uint32_t ra_ctx = -1;
    size_t tmp;

    ra_ctx = std::stoi(std::string(base64_decode<char, char>(
        (char*)req_json_obj["ra_context"].ToString().c_str(), tmp)));

    if (req_json_obj["ra_result"].ToString() == "true") {
        print_debug_message("RA has been accepted by client.", INFO);
        print_debug_message("", INFO);
    } else if (req_json_obj["ra_result"].ToString() == "false") {
        print_debug_message("RA has been rejected by client.", INFO);
        print_debug_message("", INFO);

        sgx_status_t status, retval;
        status = ecall_destroy_ra_session(eid, &retval, ra_ctx);
    } else {
        std::string error_message = "Invalid RA result format.";
        print_debug_message(error_message, ERROR);
        print_debug_message("", ERROR);

        res_json_obj["error_message"] = error_message;
        response_json = res_json_obj.dump();

        return -1;
    }

    res_json_obj["msg"] = "ok";
    response_json = res_json_obj.dump();

    return 0;
}

/* クライアントから受信したRAコンテキストのRAを破棄 */
void destruct_ra_context(sgx_enclave_id_t eid, std::string request_json) {
    print_debug_message("==============================================", INFO);
    print_debug_message("Destruct RA", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    json::JSON req_json_obj = json::JSON::Load(request_json);
    size_t tmpsz;

    std::string ra_ctx_str = std::string(base64_decode<char, char>(
        (char*)req_json_obj["ra_context"].ToString().c_str(), tmpsz));

    uint32_t ra_ctx;
    sgx_status_t retval;

    try {
        ra_ctx = std::stoi(ra_ctx_str);
    } catch (...) {
        print_debug_message("Invalid RA context format.", ERROR);
        return;
    }

    ecall_destroy_ra_session(eid, &retval, ra_ctx);

    print_debug_message("Destructed following RA context -> ", INFO);
    print_debug_message(ra_ctx_str, INFO);
    print_debug_message("", INFO);

    return;
}
