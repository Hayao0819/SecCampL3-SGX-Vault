#include "server_enclave_headers.hpp"

void unsealing_bytes(uint8_t* sealed, int sealed_len,
                     uint8_t* unsealed, int unsealed_len, int* error_flag);
sgx_status_t sealing_bytes(uint8_t* message, int message_len, uint8_t* sealed, int sealed_len, int policy);
int calc_unsealed_len(uint8_t* sealed, int sealed_len);
int strcpy_s(char* dest, std::size_t dest_size, const char* src) noexcept;

#define MRENCLAVE 0
#define MRSIGNER 1
