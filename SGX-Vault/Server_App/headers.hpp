#pragma once

#include <sgx_dcap_ql_wrapper.h>
#include <sgx_pce.h>
#include <sgx_quote_3.h>
#include <sgx_tcrypto.h>
#include <sgx_ukey_exchange.h>
#include <sgx_urts.h>
#include <sgx_uswitchless.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>
#include <thread>

#include "error_print.hpp"
#include "server_enclave_u.h"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "../common/base64.hpp"
#include "../common/crypto.hpp"
#include "../common/debug_print.hpp"
#include "../common/hexutil.hpp"
#include "../include/httplib.h"
#include "../include/ini.h"
#include "../include/json.hpp"

using namespace httplib;

// server_router.cpp で定義されている server_logics の宣言
void server_logics(sgx_enclave_id_t eid);

extern const char* config_file_path;
