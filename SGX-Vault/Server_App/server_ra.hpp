

int initialize_ra(sgx_enclave_id_t eid, std::string request_json,
                  std::string& response_json, std::string& error_message);
int get_quote(sgx_enclave_id_t eid, std::string request_json,
              std::string& response_json, std::string& error_message);

int process_ra_result(sgx_enclave_id_t eid, std::string request_json,
                      std::string& response_json, std::string& error_message);
int get_server_enclave_report(sgx_enclave_id_t eid, uint32_t ra_ctx,
                              sgx_target_info_t qe3_target_info, sgx_report_t& report);
void destruct_ra_context(sgx_enclave_id_t eid, std::string request_json);
