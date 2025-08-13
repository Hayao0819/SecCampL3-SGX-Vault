#include "client_encrypt.hpp"
#include "client_headers.hpp"
#include "client_ra.hpp"

/* TLS通信を通したリモート秘密計算のテスト */
int sample_remote_computation(std::string isv_url, std::string& ra_ctx_b64, uint8_t*& sk, uint8_t*& mk) {
    print_debug_message("==============================================", INFO);
    print_debug_message("Sample Remote Computation", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    uint64_t secret_1 = 200;
    uint64_t secret_2 = 800;
    std::string secret_1_str = std::to_string(secret_1);
    std::string secret_2_str = std::to_string(secret_2);

    print_debug_message("First integer to send -> ", INFO);
    print_debug_message(secret_1_str, INFO);
    print_debug_message("", INFO);
    print_debug_message("Second integer to send -> ", INFO);
    print_debug_message(secret_2_str, INFO);
    print_debug_message("", INFO);

    uint8_t* plain_send_1 = (uint8_t*)secret_1_str.c_str();
    uint8_t* plain_send_2 = (uint8_t*)secret_2_str.c_str();

    size_t secret_1_len = secret_1_str.length();
    size_t secret_2_len = secret_2_str.length();

    uint8_t* iv_send = new uint8_t[12]();
    uint8_t* tag_send_1 = new uint8_t[16]();
    uint8_t* tag_send_2 = new uint8_t[16]();

    /* GCM方式は平文と暗号文の長さが同一 */
    uint8_t* cipher_send_1 = new uint8_t[secret_1_len]();
    uint8_t* cipher_send_2 = new uint8_t[secret_2_len]();

    if (generate_nonce(iv_send, 12)) return -1;

    /* SKで暗号化 */
    if (-1 == (aes_128_gcm_encrypt(plain_send_1,
                                   secret_1_len, sk, iv_send, cipher_send_1, tag_send_1))) {
        return -1;
    }

    if (-1 == (aes_128_gcm_encrypt(plain_send_2,
                                   secret_2_len, sk, iv_send, cipher_send_2, tag_send_2))) {
        return -1;
    }

    char *cs1_b64, *cs2_b64;
    char* ivs_b64;
    char *tags1_b64, *tags2_b64;

    cs1_b64 = base64_encode<char, uint8_t>(cipher_send_1, secret_1_len);
    cs2_b64 = base64_encode<char, uint8_t>(cipher_send_2, secret_2_len);
    ivs_b64 = base64_encode<char, uint8_t>(iv_send, 12);
    tags1_b64 = base64_encode<char, uint8_t>(tag_send_1, 16);
    tags2_b64 = base64_encode<char, uint8_t>(tag_send_2, 16);

    json::JSON req_json_obj, res_json_obj;
    std::string request_json, response_json;

    req_json_obj["ra_context"] = ra_ctx_b64;
    req_json_obj["cipher1"] = cs1_b64;
    req_json_obj["cipher2"] = cs2_b64;
    req_json_obj["iv"] = ivs_b64;
    req_json_obj["tag1"] = tags1_b64;
    req_json_obj["tag2"] = tags2_b64;

    Client client(isv_url);

    request_json = req_json_obj.dump();

    /* 計算に使用する暗号データを送信 */
    auto res = client.Post("/sample-addition", request_json, "application/json");
    response_json = res->body;
    res_json_obj = json::JSON::Load(response_json);

    if (res->status == 500) {
        char* error_message;
        size_t error_message_size;

        error_message = base64_decode<char, char>(
            (char*)res_json_obj["error_message"].ToString().c_str(), error_message_size);

        print_debug_message(std::string(error_message), ERROR);

        return -1;
    } else if (res->status != 200) {
        std::string message = "Unexpected error while processing msg0.";
        print_debug_message(message, ERROR);
        exit(1);
    }

    /* 受信した計算結果暗号文の処理を開始 */
    uint8_t *cipher_result, *plain_result;
    uint8_t *iv_result, *tag_result;
    size_t cipher_result_len, tmpsz;

    cipher_result = base64_decode<uint8_t, char>((char*)res_json_obj["cipher"].ToString().c_str(), cipher_result_len);

    /* GCMでは暗号文と平文の長さが同一 */
    plain_result = new uint8_t[cipher_result_len]();

    iv_result = base64_decode<uint8_t, char>((char*)res_json_obj["iv"].ToString().c_str(), tmpsz);

    if (tmpsz != 12) {
        print_debug_message("Invalidly formatted IV received.", ERROR);
        return -1;
    }

    tag_result = base64_decode<uint8_t, char>((char*)res_json_obj["tag"].ToString().c_str(), tmpsz);

    if (tmpsz != 16) {
        print_debug_message("Invalidly formatted MAC tag received.", ERROR);
        return -1;
    }

    if (-1 == (aes_128_gcm_decrypt(cipher_result,
                                   cipher_result_len, mk, iv_result, tag_result, plain_result))) {
        return -1;
    }

    uint64_t total = atol((const char*)plain_result);

    /* 受信した計算結果の表示 */
    print_debug_message("Received addition result -> ", INFO);
    print_debug_message(std::to_string(total), INFO);

    return 0;
}
