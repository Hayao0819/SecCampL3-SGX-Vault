#pragma once

#include <sgx_report.h>
#include <sgx_tcrypto.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>
#include <stdlib.h>
#include <string.h>

#include <cstring>
#include <exception>
#include <map>
#include <string>
#include <vector>

#include "../common/debug_print.hpp"
#include "client_pubkey.hpp"
#include "server_enclave_t.h"

#define CLIENT_PUBKEY_NUM 2

typedef struct _ra_session_t {
    uint32_t ra_context;
    uint32_t client_id;
    sgx_ec256_public_t g_a;
    sgx_ec256_private_t server_privkey;
    sgx_ec256_public_t g_b;
    uint8_t kdk[16];
    uint8_t vk[16];
    uint8_t sk[16];
    uint8_t mk[16];
} ra_session_t;

using namespace std;
