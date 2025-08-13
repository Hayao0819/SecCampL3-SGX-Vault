#include "headers.hpp"
#include "server_ra.hpp"

/* SPから受信した2値をEnclave内で復号し加算して結果を返却 */
int encrypt_sample_addition(sgx_enclave_id_t eid, std::string request_json, std::string& response_json, std::string error_message);
