#include "client_headers.hpp"

/* settingsファイルからロードした値を格納する構造体 */
typedef struct client_settings_struct {
    std::string maa_url;
    std::string maa_api_version;
    uint32_t client_id;
    uint16_t min_isv_svn;
    uint16_t req_isv_prod_id;
    std::string req_mrenclave;
    std::string req_mrsigner;
    bool skip_mrenclave_check;
} settings_t;

extern settings_t g_settings;
std::string load_from_ini(std::string section, std::string key);

void load_settings();

/* 双方のセッション公開鍵の連結に対する署名に使用するための
 * 256bit ECDSA秘密鍵。RA中に生成するセッション鍵とは別物。 */
static const uint8_t g_client_signature_private_key[32] = {
    0xef, 0x5c, 0x38, 0xb7, 0x6d, 0x4e, 0xed, 0xce,
    0xde, 0x3b, 0x77, 0x2d, 0x1b, 0x8d, 0xa7, 0xb9,
    0xef, 0xdd, 0x60, 0xd1, 0x22, 0x50, 0xcc, 0x90,
    0xc3, 0xb5, 0x17, 0x54, 0xdc, 0x2f, 0xe5, 0x18};
