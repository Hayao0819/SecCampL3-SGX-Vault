#include "headers.hpp"
#include "server_ra.hpp"

/* SPから受信した2値をEnclave内で復号し加算して結果を返却 */
int encrypt_sample_addition(sgx_enclave_id_t eid, std::string request_json,
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

/* SPから受信したmaster_passwordをEnclave内でSealing */
int ra_setup_master_password(sgx_enclave_id_t eid, std::string request_json,
                    std::string& response_json, std::string error_message) {
    print_debug_message("==============================================", INFO);
    print_debug_message("Sample Addition", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    json::JSON req_json_obj = json::JSON::Load(request_json);

    uint8_t* cipher;
    uint8_t *iv, *tag;
    size_t cipher_len, tmpsz;
    uint32_t ra_ctx;

    // RAのセッション識別ID
    ra_ctx = std::stoi(base64_decode<char, char>((char*)req_json_obj["ra_context"].ToString().c_str(), tmpsz));

    //
    cipher = base64_decode<uint8_t, char>((char*)req_json_obj["master_password"].ToString().c_str(), cipher_len);

    // 初期化ベクトル
    iv = base64_decode<uint8_t, char>((char*)req_json_obj["iv"].ToString().c_str(), tmpsz);

    // 各cipherのタグ
    tag = base64_decode<uint8_t, char>((char*)req_json_obj["tag"].ToString().c_str(), tmpsz);

    sgx_status_t status, retval;
    uint8_t *result, *iv_result, *tag_result;
    size_t result_len;

    iv_result = new uint8_t[12]();
    tag_result = new uint8_t[16]();

    /* 結果用バッファサイズは決め打ち。uint64_t同士の加算であるため、
     * 本来は10バイトもあれば十分である。
     * 行儀よくやるのであれば、サイズ把握用の関数を用意するのが良いが、
     * 事実上二重処理になるため、行う処理の重さと相談する */
    // result = new uint8_t[32]();

    /* ECALLを行い秘密計算による加算を実行 */
    print_debug_message("Invoke ECALL for storing master key.", DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    // status = ecall_encrypt_setup_master_password(eid, &retval, ra_ctx, cipher1,
    //                                cipher1_len, cipher2, cipher2_len, iv, tag1, tag2,
    //                                result, &result_len, iv_result, tag_result);

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
