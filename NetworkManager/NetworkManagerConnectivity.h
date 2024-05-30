/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2020 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <cstring>
#include <atomic>
#include <vector>
#include <thread>
#include <chrono>
#include <map>
#include <curl/curl.h>
#include <condition_variable>
#include <mutex>
#include <cerrno>
#include <cstdlib>
#include <fstream>
#include <algorithm>
#include <ctime>

enum nsm_ipversion
{
    NSM_IPRESOLVE_WHATEVER  = 0, /* default, resolves addresses to all IP*/
    NSM_IPRESOLVE_V4        = 1, /* resolve to IPv4 addresses */
    NSM_IPRESOLVE_V6        = 2  /* resolve to IPv6 addresses */
};

enum nsm_internetState {
    NO_INTERNET,
    LIMITED_INTERNET,
    CAPTIVE_PORTAL,
    FULLY_CONNECTED,
    UNKNOWN,
};

enum nsm_connectivity_httpcode {
    HttpStatus_response_error               = 99,
    HttpStatus_200_OK                      = 200,
    HttpStatus_204_No_Content              = 204,
    HttpStatus_301_Moved_Permanentl        = 301,
    HttpStatus_302_Found                   = 302,     // captive portal
    HttpStatus_307_Temporary_Redirect      = 307,
    HttpStatus_308_Permanent_Redirect      = 308,
    HttpStatus_403_Forbidden               = 403,
    HttpStatus_404_Not_Found               = 404,
    HttpStatus_511_Authentication_Required = 511      // captive portal RFC 6585
};
