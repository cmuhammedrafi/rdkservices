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
#include <NetworkManager.h>
#include <libnm/NetworkManager.h>
#include <string.h>
#include <iostream>

class GnomeNetworkManagerEvents
{

public:
    std::string oldActiveIfaceName;
    std::string newActiveIfaceName;
    NMActiveConnection *activeConn;
    std::string ifnameWlan0;
    std::string ifnameEth0;


public:
    GnomeNetworkManagerEvents();
    ~GnomeNetworkManagerEvents();
    bool startNetworkMangerDbusEventMonitor();
    void stopNetworkMangerDbusEventMonitor();
    void startWifiScanning(std::string ssidReq = "");
    void printAvailbleAccessPoints(NMDeviceWifi *wifiDevice);

private:
    bool createClientNewConnection();

    NMClient *client;
    GMainLoop *loop;
};