#include "server_enclave_headers.hpp"

void unsealing_bytes(uint8_t* sealed, int sealed_len,
                     uint8_t* unsealed, int unsealed_len, int* error_flag);
void sealing_bytes(uint8_t* message, int message_len, uint8_t* sealed, int sealed_len, int policy);
int calc_unsealed_len(uint8_t* sealed, int sealed_len);
