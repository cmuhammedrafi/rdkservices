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

#include <curl/curl.h>
#include <resolv.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <fstream>

#include "NetworkManagerConnectivity.h"
#include "NetworkManagerLogger.h"
#include "NetworkManagerImplementation.h"

namespace WPEFramework
{
    namespace Plugin
    {

   extern NetworkManagerImplementation* _instance;

    static const char* getInternetStateString(nsm_internetState state) {
            switch(state)
            {
                case UNKNOWN: return "UNKNOWN";
                case NO_INTERNET: return "NO_INTERNET";
                case LIMITED_INTERNET: return "LIMITED_INTERNET";
                case CAPTIVE_PORTAL: return "CAPTIVE_PORTAL";
                case FULLY_CONNECTED: return "FULLY_CONNECTED";
                default: return "Unknown string";
            }
        }

    bool EndpointCache::isEndpointCashFileExist()
    {
        std::ifstream fileStream(CachefilePath);
        return fileStream.is_open();
    }

    void EndpointCache::writeEnpointsToFile(const std::vector<std::string>& endpoints)
    {
        std::ofstream outputFile(CachefilePath);
        if (outputFile.is_open())
        {
            for (const std::string& str : endpoints)
            {
                outputFile << str << '\n';
            }
            outputFile.close();
        }
        else
        {
            NMLOG_ERROR("Connectivity endpoints file write error");
        }
    }

    std::vector<std::string> EndpointCache::readEnpointsFromFile()
    {
        std::vector<std::string> readStrings;
        std::ifstream inputFile(CachefilePath);
        if (inputFile.is_open())
        {
            std::string line;
            while (std::getline(inputFile, line))
            {
                readStrings.push_back(line);
            }
            inputFile.close();
        }
        else
        {
            NMLOG_ERROR("Failed to open connectivity endpoint cache file");
        }
        return readStrings;
    }

    TestConnectivity::TestConnectivity(const std::vector<std::string>& endpoints, long timeout_ms, bool headReq, nsm_ipversion ipversion)
    {
        internetSate = UNKNOWN;
        if(endpoints.size() < 1) {
            NMLOG_ERROR("Endpoints size error ! curl check not possible");
            return;
        }

        internetSate = checkCurlResponse(endpoints, timeout_ms, headReq, ipversion);
    }

    static bool curlVerboseEnabled() {
        std::ifstream fileStream("/tmp/nm.plugin.debug");
        return fileStream.is_open();
    }

    static long current_time ()
    {
        struct timespec ts;
        clock_gettime (CLOCK_MONOTONIC, &ts);
        return (ts.tv_sec * 1000) + (ts.tv_nsec / 1000000);
    }
    static size_t writeFunction(void* ptr, size_t size, size_t nmemb, std::string* data) {
    #ifdef DBG_CURL_GET_RESPONSE
        LOG_DBG("%s",(char*)ptr);
    #endif
        return size * nmemb;
    }

    nsm_internetState TestConnectivity::checkCurlResponse(const std::vector<std::string>& endpoints, long timeout_ms,  bool headReq, nsm_ipversion ipversion)
    {
        long deadline = current_time() + timeout_ms, time_now = 0, time_earlier = 0;

        CURLM *curl_multi_handle = curl_multi_init();
        if (!curl_multi_handle)
        {
            NMLOG_ERROR("curl_multi_init returned NULL");
            return NO_INTERNET;
        }

        CURLMcode mc;
        std::vector<CURL*> curl_easy_handles;
        std::vector<int> http_responses;
        struct curl_slist *chunk = NULL;
        chunk = curl_slist_append(chunk, "Cache-Control: no-cache, no-store");
        chunk = curl_slist_append(chunk, "Connection: close");
        for (const auto& endpoint : endpoints)
        {
            CURL *curl_easy_handle = curl_easy_init();
            if (!curl_easy_handle)
            {
                NMLOG_ERROR("endpoint = <%s> curl_easy_init returned NULL", endpoint.c_str());
                continue;
            }
            curl_easy_setopt(curl_easy_handle, CURLOPT_URL, endpoint.c_str());
            curl_easy_setopt(curl_easy_handle, CURLOPT_PRIVATE, endpoint.c_str());
            /* set our custom set of headers */
            curl_easy_setopt(curl_easy_handle, CURLOPT_HTTPHEADER, chunk);
            curl_easy_setopt(curl_easy_handle, CURLOPT_USERAGENT, "RDKCaptiveCheck/1.0");
            // curl_easy_setopt(curl_easy_handle, CURLOPT_CONNECT_ONLY, 1L);
            if(headReq) {
                NMLOG_INFO("CURLOPT = Head Request");
            }
            else {
                NMLOG_INFO("CURLOPT = Get Request");
                /* HTTPGET request added insted of HTTPHEAD request fix for DELIA-61526 */
                curl_easy_setopt(curl_easy_handle, CURLOPT_HTTPGET, 1L);
            }
            curl_easy_setopt(curl_easy_handle, CURLOPT_WRITEFUNCTION, writeFunction);
            curl_easy_setopt(curl_easy_handle, CURLOPT_TIMEOUT_MS, deadline - current_time());
            if ((ipversion == CURL_IPRESOLVE_V4) || (ipversion == CURL_IPRESOLVE_V6))
                curl_easy_setopt(curl_easy_handle, CURLOPT_IPRESOLVE, ipversion);
            if(curlVerboseEnabled())
                curl_easy_setopt(curl_easy_handle, CURLOPT_VERBOSE, 1L);
            if (CURLM_OK != (mc = curl_multi_add_handle(curl_multi_handle, curl_easy_handle)))
            {
                NMLOG_ERROR("endpoint = <%s> curl_multi_add_handle returned %d (%s)", endpoint.c_str(), mc, curl_multi_strerror(mc));
                curl_easy_cleanup(curl_easy_handle);
                continue;
            }
            curl_easy_handles.push_back(curl_easy_handle);
        }
        int handles, msgs_left;
        char *url = nullptr;
    #if LIBCURL_VERSION_NUM < 0x074200
        int numfds, repeats = 0;
    #endif
        char *endpoint = nullptr;
        while (1)
        {
            if (CURLM_OK != (mc = curl_multi_perform(curl_multi_handle, &handles)))
            {
                NMLOG_ERROR("curl_multi_perform returned %d (%s)", mc, curl_multi_strerror(mc));
                break;
            }
            for (CURLMsg *msg; NULL != (msg = curl_multi_info_read(curl_multi_handle, &msgs_left)); )
            {
                long response_code = -1;
                if (msg->msg != CURLMSG_DONE)
                    continue;
                if (CURLE_OK == msg->data.result) {
                    curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &endpoint);
                    if (curl_easy_getinfo(msg->easy_handle, CURLINFO_RESPONSE_CODE, &response_code) == CURLE_OK)
                    {
                        NMLOG_TRACE("endpoint = <%s> http response code <%d>", endpoint, static_cast<int>(response_code));
                        if (HttpStatus_302_Found == response_code) {
                            if ( (curl_easy_getinfo(msg->easy_handle, CURLINFO_REDIRECT_URL, &url) == CURLE_OK) && url != nullptr) {
                                NMLOG_TRACE("captive portal found !!!");
                                captivePortalURI = url;
                            }
                        }
                    }
                }
                else
                    NMLOG_ERROR("endpoint = <%s> curl error = %d (%s)", endpoint, msg->data.result, curl_easy_strerror(msg->data.result));
                http_responses.push_back(response_code);
            }
            time_earlier = time_now;
            time_now = current_time();
            if (handles == 0 || time_now >= deadline)
                break;
    #if LIBCURL_VERSION_NUM < 0x074200
            if (CURLM_OK != (mc = curl_multi_wait(curl_multi_handle, NULL, 0, deadline - time_now, &numfds)))
            {
                LOGERR("curl_multi_wait returned %d (%s)", mc, curl_multi_strerror(mc));
                break;
            }
            if (numfds == 0)
            {
                repeats++;
                if (repeats > 1)
                    usleep(10*1000); /* sleep 10 ms */
            }
            else
                repeats = 0;
    #else
            if (CURLM_OK != (mc = curl_multi_poll(curl_multi_handle, NULL, 0, deadline - time_now, NULL)))
            {
                NMLOG_ERROR("curl_multi_poll returned %d (%s)", mc, curl_multi_strerror(mc));
                break;
            }
    #endif
        }

        if(curlVerboseEnabled()) {
            NMLOG_TRACE("endpoints count = %d response count %d, handles = %d, deadline = %ld, time_now = %ld, time_earlier = %ld",
                static_cast<int>(endpoints.size()), static_cast<int>(http_responses.size()), handles, deadline, time_now, time_earlier);
        }

        for (const auto& curl_easy_handle : curl_easy_handles)
        {
            curl_easy_getinfo(curl_easy_handle, CURLINFO_PRIVATE, &endpoint);
            //LOG_DBG("endpoint = <%s> terminating attempt", endpoint);
            curl_multi_remove_handle(curl_multi_handle, curl_easy_handle);
            curl_easy_cleanup(curl_easy_handle);
        }
        curl_multi_cleanup(curl_multi_handle);
        /* free the custom headers */
        curl_slist_free_all(chunk);
        return checkInternetStateFromResponseCode(http_responses);
    }

    /*
    * verifying Most occurred response code is 50 % or more
    * Example 1 :
    *      if we have 5 endpoints so response also 5 ( 204 302 204 204 200 ) . Here count is 204 :- 3, 302 :- 1, 200 :- 1
    *      Return Internet State: FULLY_CONNECTED - 60 %
    * Example 2 :
    *      if we have 4 endpoints so response also 4 ( 204 204 200 200 ) . Here count is 204 :- 2, 200 :- 2
    *      Return Internet State: FULLY_CONNECTED - 50 %
    */

    nsm_internetState TestConnectivity::checkInternetStateFromResponseCode(const std::vector<int>& responses)
    {
        nsm_internetState InternetConnectionState = NO_INTERNET;
        nsm_connectivity_httpcode http_response_code = HttpStatus_response_error;

        int max_count = 0;
        for (int element : responses)
        {
            int element_count = count(responses.begin(), responses.end(), element);
            if (element_count > max_count)
            {
                http_response_code = static_cast<nsm_connectivity_httpcode>(element);
                max_count = element_count;
            }
        }

        /* Calculate the percentage of the most frequent code occurrences */
        float percentage = (static_cast<float>(max_count) / responses.size());

        /* 50 % connectivity check */
        if (percentage >= 0.5)
        {
            switch (http_response_code)
            {
                case HttpStatus_204_No_Content:
                    InternetConnectionState = FULLY_CONNECTED;
                    NMLOG_INFO("Internet State: FULLY_CONNECTED - %.1f%%", (percentage*100));
                break;
                case HttpStatus_200_OK:
                    InternetConnectionState = LIMITED_INTERNET;
                    NMLOG_INFO("Internet State: LIMITED_INTERNET - %.1f%%", (percentage*100));
                break;
                case HttpStatus_511_Authentication_Required:
                case HttpStatus_302_Found:
                    InternetConnectionState = CAPTIVE_PORTAL;
                    NMLOG_INFO("Internet State: CAPTIVE_PORTAL - %.1f%%", (percentage*100));
                break;
                default:
                    InternetConnectionState = NO_INTERNET;
                    if(http_response_code == -1)
                        NMLOG_ERROR("Internet State: NO_INTERNET (curl error)");
                    else
                        NMLOG_WARNING("Internet State: NO_INTERNET (http code: %d - %.1f%%)", static_cast<int>(http_response_code), percentage * 100);
                    break;
            }
        }
        return InternetConnectionState;
    }

    static bool checkConnectionToDnsServer(const std::string& dnsIP)
    {
        int port = 53; // Default DNS port

        if (dnsIP.find(':') != std::string::npos) // IPv6 address
        {
            int sockfd = socket(AF_INET6, SOCK_STREAM, 0);
            if (sockfd == -1)
            {
                    NMLOG_ERROR("Error creating socket.");
                    return false;
            }

            struct sockaddr_in6 serverAddr6;
            serverAddr6.sin6_family = AF_INET6;
            serverAddr6.sin6_port = htons(port);
            if (inet_pton(AF_INET6, dnsIP.c_str(), &(serverAddr6.sin6_addr)) <= 0)
            {
                    NMLOG_ERROR("Invalid address/ Address not supported");
                    return false;
            }

            if (connect(sockfd, (struct sockaddr*)&serverAddr6, sizeof(serverAddr6)) == 0)
            {
                    NMLOG_INFO("DNS Server IP : %s Success", dnsIP.c_str());
                    close(sockfd);
                    return true;
            }

            close(sockfd);
        }
        else // IPv4 address
        {
            int sockfd = socket(AF_INET, SOCK_STREAM, 0);
            if (sockfd == -1)
            {
                    NMLOG_ERROR("Error creating socket.");
                    return false;
            }

            struct sockaddr_in serverAddr;
            serverAddr.sin_family = AF_INET;
            serverAddr.sin_port = htons(port);
            serverAddr.sin_addr.s_addr = inet_addr(dnsIP.c_str());

            if (connect(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == 0)
            {
                    NMLOG_INFO("DNS Server IP : %s Success", dnsIP.c_str());
                    close(sockfd);
                    return true;
            }

            close(sockfd);
        }
        return false;
    }

    bool TestConnectivity::checkDnsConnection()
    {
        std::ifstream file(NMCONNECTIVITY_DNS_RESOLVE_FILE);
        if (!file.is_open())
        {
            NMLOG_ERROR("Could not open file %s", NMCONNECTIVITY_DNS_RESOLVE_FILE);
            return false;
        }

        std::string str;
        while (std::getline(file, str))
        {
            if(str.substr(0, 10) == "nameserver")
            {
                std::string ip = str.substr(11);
                if(!ip.empty() && ip.size() > 3)
                {
                    if(checkConnectionToDnsServer(ip))
                        return true;
                    else
                        NMLOG_ERROR("DNS IP Connection : %s Failed", ip.c_str());
                }
            }
        }
        return false;
    }

    ConnectivityMonitor::ConnectivityMonitor()
    {
        capitiveEndpt.push_back("http://clients3.google.com/generate_204");
        if(endpointCache.isEndpointCashFileExist())
        {
            std::vector<std::string> cachedEndPnt = endpointCache.readEnpointsFromFile();
            setConnMonitorEndpoint(cachedEndPnt);
            NMLOG_INFO("cached connectivity endpoints loaded");
        }
        else
            connMonitorEndpt.push_back("http://clients3.google.com/generate_204");

        isCaptivePortalFound = false;
        stopConnMonitor = true;
        doCaptiveTest = true;
        doConnectivityTest = false;
    }

    ConnectivityMonitor::~ConnectivityMonitor()
    {
        NMLOG_WARNING("~ConnectivityMonitor");
        killConnectivityMonitor();
    }

    void ConnectivityMonitor::readConnectivityMonitorConf(const std::string& configFilePath)
    {
        std::ifstream configFile(configFilePath);
        if (!configFile.is_open())
        {
            NMLOG_ERROR("Unable to open the configuration file: %s", configFilePath.c_str());
            return;
        }

        bool ConnectivityConfigFound = false;
        std::map<std::string, std::string> configMap;
        int configMonitorInterval = 0;
        bool configMonitorConnectivityEnabled = false;
        // load connectivity endpoint configuration from conf file
        std::string line;
        while (std::getline(configFile, line))
        {
            if (line == "[Connectivity_Config]")
            {
                ConnectivityConfigFound = true;
                continue;
            }

            if (ConnectivityConfigFound)
            {
                size_t equalsPos = line.find('=');
                if (equalsPos != std::string::npos)
                {
                    std::string key = line.substr(0, equalsPos);
                    std::string value = line.substr(equalsPos + 1);
                    configMap[key] = value;
                }
            }
        }

        configFile.close();
        /* Parse the connectivity monitor interval and enable values */
        configMonitorConnectivityEnabled = ((configMap["CONNECTIVITY_MONITOR_ENABLE"] == "1")? true:false);
        std::string monitorIntervalStr = configMap["CONNECTIVITY_MONITOR_INTERVAL"];
        if (!monitorIntervalStr.empty())
        {
            configMonitorInterval = std::stoi(monitorIntervalStr);
        }

        capitiveEndpt.clear();
        for (int i = 1; i <= 5; ++i)
        {
            std::string endpointName = "CONNECTIVITY_ENDPOINT_" + std::to_string(i);
            auto endpoint = configMap.find(endpointName);
            if (endpoint != configMap.end() && endpoint->second.length() > 3)
            {
                capitiveEndpt.push_back(endpoint->second);
            }
        }

        if(capitiveEndpt.empty())
        {
            NMLOG_ERROR("captive endpoints are empty set default public endpoint set !!");
            capitiveEndpt.push_back("http://clients3.google.com/generate_204");
        }
        else
        {
            std::string endpoints_str;
            for (const auto& endpoint : capitiveEndpt)
                endpoints_str.append(endpoint).append(" ");
            NMLOG_INFO("captive portal endpoints count %d and endpoints:- %s", static_cast<int>(capitiveEndpt.size()), endpoints_str.c_str());
            NMLOG_INFO("default monitor connectivity interval: %d and monitor connectivity auto start : %s", configMonitorInterval, configMonitorConnectivityEnabled? "true":"false");
        }
    }

    bool ConnectivityMonitor::isConnectedToInternet(nsm_ipversion ipversion)
    {
        if (nsm_internetState::FULLY_CONNECTED == getInternetState(ipversion))
        {
            NMLOG_INFO("isConnectedToInternet %s = true", (ipversion == nsm_ipversion::NSM_IPRESOLVE_WHATEVER)?"":(ipversion == nsm_ipversion::NSM_IPRESOLVE_V4? "IPv4":"IPv6"));
            return true;
        }
        NMLOG_WARNING("isConnectedToInternet %s = false",(ipversion == nsm_ipversion::NSM_IPRESOLVE_WHATEVER)?"":(ipversion == nsm_ipversion::NSM_IPRESOLVE_V4? "IPv4":"IPv6") );
        return false;
    }

    nsm_internetState ConnectivityMonitor::getInternetState(nsm_ipversion ipversion)
    {
        nsm_internetState internetState = nsm_internetState::UNKNOWN;
        // If monitor connectivity is running take the cache value
        if( isConnectivityMonitorRunnig() &&
            (ipversion == NSM_IPRESOLVE_WHATEVER) && (gInternetState != nsm_internetState::UNKNOWN) )
        {
            internetState = gInternetState;
            NMLOG_TRACE("Cached internet state %s ", getInternetStateString(internetState));
        }
        else
        {
            if(isCaptivePortalFound)
            {
                TestConnectivity testInternet(capitiveEndpt, NMCONNECTIVITY_CURL_REQUEST_TIMEOUT_MS, NMCONNECTIVITY_CURL_GET_REQUEST, ipversion);
                internetState = testInternet.getInternetState();
            }
            else
            {
                TestConnectivity testInternet(connMonitorEndpt, NMCONNECTIVITY_CURL_REQUEST_TIMEOUT_MS, NMCONNECTIVITY_CURL_HEAD_REQUEST, ipversion);
                internetState = testInternet.getInternetState();
            }
        }
        return internetState;
    }

    std::string ConnectivityMonitor::getCaptivePortalURI()
    {
        TestConnectivity testInternet(capitiveEndpt, NMCONNECTIVITY_CURL_REQUEST_TIMEOUT_MS, NMCONNECTIVITY_CURL_GET_REQUEST, NSM_IPRESOLVE_WHATEVER);
        if(nsm_internetState::CAPTIVE_PORTAL == testInternet.getInternetState())
        {
            NMLOG_WARNING("captive portal URI = %s", testInternet.getCaptivePortal().c_str());
            return testInternet.getCaptivePortal();
        }
        NMLOG_WARNING("No captive portal found !");
        return std::string("");
    }

    bool ConnectivityMonitor::startConnectivityMonitor(int timeoutInSeconds)
    {
        if (connectivityMonitorDisabled)
        {
            NMLOG_ERROR("connectivityMonitorDisabled");
            return false;
        }

        doConnectivityTest = true;

        connMonitorTimeout.store(timeoutInSeconds >= NMCONNECTIVITY_MONITOR_MIN_INTERVAL ? timeoutInSeconds : NMCONNECTIVITY_MONITOR_DEFAULT_INTERVAL);
        if (connMonitorThrd.joinable() && stopConnMonitor == false)
        {
            if(doCaptiveTest)
            {
                NMLOG_INFO("captive monitor running so new interval updated with %d Sec", connMonitorTimeout.load());
            }
            else
            {
                NMLOG_INFO("connectivity monitor restarted with %d Sec", connMonitorTimeout.load());
                cvConnMonitor.notify_all();
            }
            return true;
        }

        stopConnMonitor = true;
        if (connMonitorThrd.joinable())
            connMonitorThrd.join();

        stopConnMonitor = false;
        doCaptiveTest = false; /* start with head request */
        connMonitorThrd = std::thread(&ConnectivityMonitor::connectivityMonitorFunction, this);
        NMLOG_INFO("connectivity monitor started with %d Sec", connMonitorTimeout.load());

        if(connMonitorThrd.joinable())
        {
            return true;
        }
        else
            NMLOG_ERROR("Connectivity monitor start Failed");

        return false;
    }

    bool ConnectivityMonitor::stopConnectivityMonitor()
    {
        doConnectivityTest = false;
        if(doCaptiveTest)
        {
            /* captive portal check need to continoue even after this fuction called */
            NMLOG_INFO("connectivity Monitor stopped but captive check is running");
            return true;
        }
        stopConnMonitor = true;
        cvConnMonitor.notify_all();

        if (connMonitorThrd.joinable())
            connMonitorThrd.join();
        NMLOG_INFO("Connectivity Monitor stopped");
        return true;
    }

    bool ConnectivityMonitor::isConnectivityMonitorRunnig()
    {
        return (connMonitorThrd.joinable() && (stopConnMonitor == false));
    }

    bool ConnectivityMonitor::startCaptivePortalMonitor()
    {
        /* NetworkManagerImplementation not require to start */
        if (connectivityMonitorDisabled) {
            NMLOG_ERROR("connectivityMonitorDisabled");
            return false;
        }

        doCaptiveTest = true; /* start with Get request */
        if (isConnectivityMonitorRunnig())
        {
            cvConnMonitor.notify_all();
            NMLOG_INFO("trigger connectivity monitor");
            return true;
        }

        if (connMonitorThrd.joinable())
        {
            stopConnMonitor = true;
            cvConnMonitor.notify_all();
            connMonitorThrd.join();
        }

        stopConnMonitor = false;
        connMonitorThrd = std::thread(&ConnectivityMonitor::connectivityMonitorFunction, this);
        if (connMonitorThrd.joinable())
        {
            NMLOG_INFO("captive portal monitor started ");
        }
        return true;
    }

    void ConnectivityMonitor::notifyInternetStatusChangedEvent(nsm_internetState newInternetState)
    {
        if(_instance != nullptr)
        {
            Exchange::INetworkManager::InternetStatus oldState = static_cast<Exchange::INetworkManager::InternetStatus>(gInternetState.load());
            Exchange::INetworkManager::InternetStatus newState = static_cast<Exchange::INetworkManager::InternetStatus>(newInternetState);
            _instance->ReportInternetStatusChangedEvent(oldState , newState);
        }
        else
            NMLOG_WARNING("NetworkManagerImplementation Instance NULL notifyInternetStatusChange failed.");
    }

    void ConnectivityMonitor::connectivityMonitorFunction()
    {
        int TempInterval = connMonitorTimeout.load();
        bool curlCheckTyp = NMCONNECTIVITY_CURL_HEAD_REQUEST;
        std::vector<std::string> tempTestEndpt;
        std::mutex connMutex;
        int retryCount = NMCONNECTIVITY_NO_INTERNET_RETRY_COUNT;
        nsm_internetState currentInternetState = nsm_internetState::UNKNOWN;

        while(!stopConnMonitor)
        {
            if(doCaptiveTest)
            {
                tempTestEndpt = capitiveEndpt;
                TempInterval = NMCONNECTIVITY_CAPTIVE_MONITOR_INTERVAL;
                curlCheckTyp = NMCONNECTIVITY_CURL_GET_REQUEST;
            }
            else
            {
                tempTestEndpt = connMonitorEndpt;
                TempInterval = connMonitorTimeout.load();
                curlCheckTyp = NMCONNECTIVITY_CURL_HEAD_REQUEST;
            }

            TestConnectivity testInternet(tempTestEndpt, NMCONNECTIVITY_CURL_REQUEST_TIMEOUT_MS, curlCheckTyp, NSM_IPRESOLVE_WHATEVER);
            currentInternetState = testInternet.getInternetState();

            if(stopConnMonitor)
                break;

            switch (currentInternetState)
            {
                case nsm_internetState::NO_INTERNET:
                {
                    if ( curlCheckTyp == NMCONNECTIVITY_CURL_GET_REQUEST )  // captive portal check
                    {
                        isCaptivePortalFound = false;
                        TempInterval = 15; // 15 sec
                    }
                    else    // normal connectivity check
                    {
                        TempInterval = 5; // 5 Sec for next retry check
                        retryCount--;
                        if(retryCount >= 0)
                        {
                            NMLOG_INFO("Internet connection  Failed. Retrying %d in 5 Sec", NMCONNECTIVITY_NO_INTERNET_RETRY_COUNT - retryCount);
                            currentInternetState = gInternetState ; // new state same as prvious state so i will not post internet state change
                        }
                        else
                        {
                            // TODO DNS check if needed
                            retryCount = NMCONNECTIVITY_NO_INTERNET_RETRY_COUNT;
                            TempInterval = connMonitorTimeout.load();
                        }
                    }
                break;
                }
                case nsm_internetState::LIMITED_INTERNET:
                    retryCount = NMCONNECTIVITY_NO_INTERNET_RETRY_COUNT;
                    isCaptivePortalFound = false;
                break;
                case nsm_internetState::CAPTIVE_PORTAL:
                {
                    TempInterval = NMCONNECTIVITY_CAPTIVE_MONITOR_INTERVAL;
                    curlCheckTyp == NMCONNECTIVITY_CURL_GET_REQUEST;
                    isCaptivePortalFound = true;
                }
                break;
                case nsm_internetState::FULLY_CONNECTED:
                {
                    if(curlCheckTyp == NMCONNECTIVITY_CURL_GET_REQUEST)       // captive portal check
                    {
                        doCaptiveTest = false;
                        if(doConnectivityTest)
                        {
                            // TempInterval = connMonitorTimeout.load();
                            retryCount = NMCONNECTIVITY_NO_INTERNET_RETRY_COUNT;
                        }
                        else    // we don't need this thread when fully connected in captive portal check so exiting
                        {
                            stopConnMonitor = true;
                            gInternetState = nsm_internetState::UNKNOWN; // make sure last event will post
                        }
                    }
                    isCaptivePortalFound = false;
                    TempInterval = connMonitorTimeout.load();
                }
                break;
                default:
                    NMLOG_WARNING("internet state not handiled %s", getInternetStateString(currentInternetState));
                    break;
            }

            if(gInternetState != currentInternetState)
            {
                gInternetState = currentInternetState;
                /* Notify Internet state change */
                notifyInternetStatusChangedEvent(currentInternetState);
                NMLOG_INFO("Internet state changed to %s", getInternetStateString(currentInternetState));
            }

            if(stopConnMonitor)
                break;
            /* wait for next interval */
            std::unique_lock<std::mutex> lock(connMutex);
            if (cvConnMonitor.wait_for(lock, std::chrono::seconds(TempInterval)) != std::cv_status::timeout)
            {
                if(!stopConnMonitor)
                {
                    NMLOG_INFO("connectivity monitor recieved signal. Skping %d sec interval", TempInterval);
                }
            }
            else
                NMLOG_INFO("connectivity monitor %d sec interval expired", TempInterval);
        };
        stopConnMonitor = true;
        gInternetState = nsm_internetState::UNKNOWN;
        NMLOG_TRACE("connectivity monitor exit");
    }

    void ConnectivityMonitor::setConnMonitorEndpoint(const std::vector<std::string> &endpoints)
    {
        connMonitorEndpt.clear();
        for (auto endpoint : endpoints) {
            if(!endpoint.empty() && endpoint.size() > 3)
                connMonitorEndpt.push_back(endpoint.c_str());
            else
                NMLOG_ERROR("endpoint not vallied = %s", endpoint.c_str());
        }

        // write the endpoints to a file
        endpointCache.writeEnpointsToFile(connMonitorEndpt);

        std::string endpointsStr;
        for (const auto& endpoint : connMonitorEndpt)
            endpointsStr.append(endpoint).append(" ");
        NMLOG_INFO("Connectivity monitor endpoints -: %d :- %s", static_cast<int>(connMonitorEndpt.size()), endpointsStr.c_str());
    }

    void ConnectivityMonitor::setCaptiveMonitorEndpoint(const std::vector<std::string> &endpoints)
    {
        capitiveEndpt.clear();
        for (auto endpoint : endpoints) {
            if(!endpoint.empty() && endpoint.size() > 3)
                capitiveEndpt.push_back(endpoint.c_str());
            else
                NMLOG_ERROR("endpoint not vallied = %s", endpoint.c_str());
        }

        std::string endpointsStr;
        for (const auto& endpoint : capitiveEndpt)
            endpointsStr.append(endpoint).append(" ");
        NMLOG_INFO("captive monitor endpoints -: %d :- %s", static_cast<int>(capitiveEndpt.size()), endpointsStr.c_str());
    }

    bool ConnectivityMonitor::killConnectivityMonitor()
    {
        connectivityMonitorDisabled = true;
        stopConnMonitor = true;
        cvConnMonitor.notify_all();
        if (connMonitorThrd.joinable())
        {
            connMonitorThrd.join();
            NMLOG_INFO("connectivity monitor stopped permanetly");
        }
        else
            NMLOG_INFO("no connectivity monitor running");
        return true;
    }

    } // namespace Plugin
} // namespace WPEFramework
