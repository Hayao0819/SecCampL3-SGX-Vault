#include "headers.hpp"
#include "server_handler.hpp"
#include "server_ra.hpp"

/* サーバの実行定義。RA含む各処理はここで完結する */
void server_logics(sgx_enclave_id_t eid) {
    Server svr;

    svr.Post("/init-ra", [&](const Request& req, Response& res) {
        print_debug_message(std::string("[REQ] /init-ra: ") + req.body, INFO);
        handler_init_ra(eid, req, res);
    });
    svr.Post("/get-quote", [&](const Request& req, Response& res) {
        print_debug_message(std::string("[REQ] /get-quote: ") + req.body, INFO);
        handler_get_quote(eid, req, res);
    });
    svr.Post("/ra-result", [&](const Request& req, Response& res) {
        print_debug_message(std::string("[REQ] /ra-result: ") + req.body, INFO);
        handler_ra_result(eid, req, res);
    });

    /* リモート計算処理テスト（受信した秘密情報のEnclave内での加算） */
    svr.Post("/sample-addition", [&eid](const Request& req, Response& res) {
        print_debug_message(std::string("[REQ] /sample-addition: ") + req.body, INFO);
        handler_sample_addition(eid, req, res);
    });
    svr.Post("/destruct-ra", [&](const Request& req, Response& res) {
        print_debug_message(std::string("[REQ] /destruct-ra: ") + req.body, INFO);
        handler_destruct_ra(eid, req, res);
    });
    svr.Get("/hi", [](const Request& req, Response& res) {
        print_debug_message("[REQ] /hi", INFO);
        handler_hi(req, res);
    });
    svr.Get("/stop", [&](const Request& req, Response& res) {
        print_debug_message("[REQ] /stop", INFO);
        handler_stop(eid, svr, req, res);
    });
    svr.Get("/status", [&](const Request& req, Response& res) {
        print_debug_message("[REQ] /status", INFO);
        handler_status(eid, req, res);
    });
    svr.Post("/set-masterkey", [&](const Request& req, Response& res) {
        print_debug_message(std::string("[REQ] /set-masterkey: ") + req.body, INFO);
        handler_set_masterkey(eid, req, res);
    });
    svr.Post("/store-password", [&](const Request& req, Response& res) {
        std::string log_msg = std::string("[REQ] /store-password: body=[") + req.body + "] key=[" + req.get_param_value("key") + "] value=[" + req.get_param_value("value") + "]";
        print_debug_message(log_msg, INFO);
        handler_store_password(eid, req, res);
    });
    svr.Post("/get-password", [&](const Request& req, Response& res) {
        std::string log_msg = std::string("[REQ] /get-password: key=[") + req.get_param_value("key") + "]";
        print_debug_message(log_msg, INFO);
        handler_get_password(eid, req, res);
    });

    svr.listen("localhost", 1234);
}
