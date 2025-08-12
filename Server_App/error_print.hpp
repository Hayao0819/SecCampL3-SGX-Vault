#pragma once
#include <sgx_error.h>
#include <sgx_ql_lib_common.h>

#include <iostream>

void print_sgx_status(sgx_status_t status);

void print_ql_status(quote3_error_t qe3_error);

// error_print.cpp で定義されている関数

#ifdef __cplusplus
extern "C" {
#endif
void ocall_print(const char* str, int log_type);
void ocall_print_status(sgx_status_t st);
void ocall_print_binary(uint8_t* buf, size_t sz);
#ifdef __cplusplus
}
#endif
