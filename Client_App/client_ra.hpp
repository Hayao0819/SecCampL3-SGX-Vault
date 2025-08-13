#ifndef CLIENT_RA_HPP
#define CLIENT_RA_HPP

#include <stddef.h>

#include <cstdint>
#include <string>

// RAセッション中に発生する鍵関係コンテキスト用構造体
typedef struct ra_session_struct {
    uint8_t g_a[64];
    uint8_t g_b[64];
    uint8_t kdk[16];
    uint8_t vk[16];
    uint8_t sk[16];
    uint8_t mk[16];
} ra_session_t;

// クライアント向けのsgx_ec256_signature_tの定義
typedef struct _client_sgx_ec256_signature_t {
    uint32_t x[8];
    uint32_t y[8];
} client_sgx_ec256_signature_t;

int initialize_ra(std::string server_url,
                  std::string& ra_ctx_b64, ra_session_t& ra_keys);
int generate_kdk(void* Gb, ra_session_t& ra_keys);  // EVP_PKEY* Gb
int process_session_keys(ra_session_t& ra_keys,
                         client_sgx_ec256_signature_t& sigsp);
int get_quote(std::string server_url, std::string ra_ctx_b64,
              ra_session_t ra_keys, client_sgx_ec256_signature_t sigsp,
              std::string& quote_json);
int send_quote_to_maa(std::string quote_json, std::string& ra_report_jwt);
int verify_enclave(std::string ra_report_jwt,
                   std::string quote_json, ra_session_t ra_keys);
int process_ra_report(std::string ra_report_jwt,
                      std::string quote_json, ra_session_t ra_keys);
int send_ra_result(std::string server_url,
                   std::string ra_ctx_b64, bool ra_result);
int do_RA(std::string server_url,
          std::string& ra_ctx_b64, uint8_t*& sk, uint8_t*& mk);
void destruct_ra_context(std::string server_url, std::string ra_ctx_b64);
int generate_nonce(uint8_t* buf, size_t size);
int aes_128_gcm_encrypt(uint8_t* plaintext, size_t p_len,
                        uint8_t* key, uint8_t* iv, uint8_t* ciphertext, uint8_t* tag);
int aes_128_gcm_decrypt(uint8_t* ciphertext, size_t c_len,
                        uint8_t* key, uint8_t* iv, uint8_t* tag, uint8_t* plaintext);

#endif  // CLIENT_RA_HPP
