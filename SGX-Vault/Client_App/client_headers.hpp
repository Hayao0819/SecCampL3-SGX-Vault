#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <sgx_report.h>
#include <string.h>

#include <algorithm>
#include <iostream>
#include <string>

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "../common/base64.hpp"
#include "../common/crypto.hpp"
#include "../common/debug_print.hpp"
#include "../common/hexutil.hpp"
#include "../common/jwt_util.hpp"
#include "../include/httplib.h"
#include "../include/ini.h"
#include "../include/json.hpp"

using namespace httplib;

