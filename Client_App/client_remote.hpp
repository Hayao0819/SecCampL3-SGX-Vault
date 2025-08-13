#include "client_encrypt.hpp"
#include "client_headers.hpp"
#include "client_ra.hpp"

/* TLS通信を通したリモート秘密計算のテスト */
int sample_remote_computation(std::string isv_url,
                              std::string& ra_ctx_b64, uint8_t*& sk, uint8_t*& mk);
