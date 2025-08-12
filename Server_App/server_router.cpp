
#include "headers.hpp"
#include "server_ra.hpp"
#include "server_service.hpp"

/* サーバの実行定義。RA含む各処理はここで完結する */
void server_logics(sgx_enclave_id_t eid) {
    Server svr;

    svr.Post("/init-ra", [&](const Request& req, Response& res) {
        handler_init_ra(eid, req, res);
    });
    svr.Post("/get-quote", [&](const Request& req, Response& res) {
        handler_get_quote(eid, req, res);
    });
    svr.Post("/ra-result", [&](const Request& req, Response& res) {
        handler_ra_result(eid, req, res);
    });

    /* リモート計算処理テスト（受信した秘密情報のEnclave内での加算） */
    svr.Post("/sample-addition", [&eid](const Request& req, Response& res) {
        handler_sample_addition(eid, req, res);
    });
    svr.Post("/destruct-ra", [&](const Request& req, Response& res) {
        handler_destruct_ra(eid, req, res);
    });
    svr.Get("/hi", [](const Request& req, Response& res) {
        handler_hi(req, res);
    });
    svr.Get("/stop", [&](const Request& req, Response& res) {
        handler_stop(eid, svr, req, res);
    });
    svr.Get("/status", [&](const Request& req, Response& res) {
        handler_status(eid, req, res);
    });
    svr.Post("/set-password", [&](const Request& req, Response& res) {
        handler_set_password(eid, req, res);
    });

    svr.listen("localhost", 1234);
}
