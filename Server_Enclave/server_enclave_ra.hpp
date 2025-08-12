#include "server_enclave_headers.hpp"

sgx_status_t ecall_process_session_keys(uint32_t ra_ctx,
                                        uint32_t client_id, sgx_ec256_public_t* Gb,
                                        sgx_ec256_signature_t* sigsp);

extern std::vector<ra_session_t> g_ra_sessions;
