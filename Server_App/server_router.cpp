
#include "headers.hpp"
#include "server_ra.hpp"
#include "server_service.hpp"

/* サーバの実行定義。RA含む各処理はここで完結する */
void server_logics(sgx_enclave_id_t eid) {
    Server svr;

    svr.Post("/init-ra", [&](const Request& req, Response& res) {
        std::string response_json, error_message = "";
        std::string request_json = req.body;

        int ret = initialize_ra(eid,
                                request_json, response_json, error_message);

        if (!ret)
            res.status = 200;
        else {
            /* 通信用にBase64化 */
            char* error_message_b64;
            error_message_b64 = base64_encode<char, char>(
                (char*)error_message.c_str(), error_message.length());

            /* レスポンス用jsonを生成 */
            json::JSON json_obj;
            json_obj["error_message"] = std::string(error_message_b64);
            response_json = json_obj.dump();

            res.status = 500;
        }

        /* レスポンスを返信 */
        res.set_content(response_json, "application/json");
    });

    svr.Post("/get-quote", [&](const Request& req, Response& res) {
        std::string request_json = req.body;
        std::string response_json, error_message = "";

        int ret = get_quote(eid, request_json, response_json, error_message);

        print_debug_message("Quote JSON ->", DEBUG_LOG);
        print_debug_message(response_json, DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);

        if (!ret)
            res.status = 200;
        else {
            /* 通信用にBase64化 */
            char* error_message_b64;
            error_message_b64 = base64_encode<char, char>(
                (char*)error_message.c_str(), error_message.length());

            /* レスポンス用jsonを生成 */
            json::JSON json_obj;
            json_obj["error_message"] = std::string(error_message_b64);
            response_json = json_obj.dump();

            res.status = 500;
        }

        /* レスポンスを返信 */
        res.set_content(response_json, "application/json");
    });

    svr.Post("/ra-result", [&](const Request& req, Response& res) {
        std::string request_json = req.body;
        std::string response_json, error_message = "";

        int ret = process_ra_result(eid,
                                    request_json, response_json, error_message);

        if (!ret)
            res.status = 200;
        else {
            /* 通信用にBase64化 */
            char* error_message_b64;
            error_message_b64 = base64_encode<char, char>(
                (char*)error_message.c_str(), error_message.length());

            /* レスポンス用jsonを生成 */
            json::JSON json_obj;
            json_obj["error_message"] = std::string(error_message_b64);
            response_json = json_obj.dump();

            res.status = 500;
        }

        /* レスポンスを返信 */
        res.set_content(response_json, "application/json");
    });

    /* リモート計算処理テスト（受信した秘密情報のEnclave内での加算） */
    svr.Post("/sample-addition", [&eid](const Request& req, Response& res) {
        std::string request_json = req.body;
        std::string response_json, error_message = "";

        int ret = sample_addition(eid, request_json,
                                  response_json, error_message);

        if (!ret)
            res.status = 200;
        else {
            json::JSON res_json_obj;
            char* error_message_b64;

            error_message_b64 = base64_encode<char, char>(
                (char*)error_message.c_str(), error_message.length());

            res_json_obj["error_message"] = std::string(error_message_b64);
            response_json = res_json_obj.dump();

            res.status = 500;
        }

        print_debug_message("send the result response to SP.", INFO);
        print_debug_message("", INFO);

        res.set_content(response_json, "application/json");
    });

    svr.Post("/destruct-ra", [&](const Request& req, Response& res) {
        std::string request_json = req.body;
        std::string response_json, error_message = "";

        destruct_ra_context(eid, request_json);

        res.status = 200;
        json::JSON res_json_obj;
        res_json_obj["message"] = std::string("OK");
        response_json = res_json_obj.dump();

        res.set_content(response_json, "application/json");
    });

    svr.Get("/hi", [](const Request& req, Response& res) {
        res.set_content("Hello World!", "text/plain");
    });

    svr.Get("/stop", [&](const Request& req, Response& res) {
        /* Enclaveの終了 */
        sgx_destroy_enclave(eid);

        svr.stop();
    });

    svr.listen("localhost", 1234);
}
