#include "client_headers.hpp"
#include "client_ra.hpp"
#include "client_settings.hpp"
#include "client_remote.hpp"

void main_process() {
    /* 設定ファイルからの設定の読み取り */
    load_settings();

    /* SGXサーバのURLを設定 */
    std::string server_url = "http://localhost:1234";

    /* SGXサーバはこの変数を用いてSP（厳密にはRA）の識別を行う。
     * SPは直接は使わないので、通信向けにbase64の形で保持 */
    std::string ra_ctx_b64 = "";

    /* RA後のTLS通信用のセッション鍵（共有秘密）。
     * do_RA関数内で取得され引数経由で返される。 */
    uint8_t *sk, *mk;

    int ret = -1;

    /* RAを実行 */
    ret = do_RA(server_url, ra_ctx_b64, sk, mk);

    if (ret) {
        std::string message = "RA failed. Clean up and exit program.";
        print_debug_message(message, ERROR);

        destruct_ra_context(server_url, ra_ctx_b64);

        exit(0);
    }

    print_debug_binary("SK", sk, 16, DEBUG_LOG);
    print_debug_binary("MK", mk, 16, DEBUG_LOG);

    /* TLS通信を通したリモート秘密計算のテスト */
    ret = sample_remote_computation(server_url, ra_ctx_b64, sk, mk);

    delete[] sk;
    delete[] mk;

    /* RAコンテキストの破棄 */
    destruct_ra_context(server_url, ra_ctx_b64);
}

int main() {
    std::string message = "Launched SP's untrusted application.";
    print_debug_message(message, INFO);

    main_process();

    return 0;
}
