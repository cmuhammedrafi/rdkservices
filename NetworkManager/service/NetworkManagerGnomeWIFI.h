
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
#include "NetworkManagerLogger.h"
#include "INetworkManager.h"
#include <iostream>
#include <glib.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define NM_FLAGS_ANY(flags, check) (((flags) & (check)) != 0)
namespace WPEFramework
{
    namespace Plugin
    {
        class wifiManager
        {
        public:
            static wifiManager* getInstance()
            {
                static wifiManager instance;
                return &instance;
            }

            bool isWifiConnected();
            bool wifiDisconnect();
            bool wifiConnectedSSIDInfo(Exchange::INetworkManager::WiFiSSIDInfo &ssidinfo);
            bool wifiConnect(const char *ssid_in, const char* password_in, Exchange::INetworkManager::WIFISecurityMode security_in);
            bool quit(NMDevice *wifiNMDevice);
            bool wait(GMainLoop *loop);
        private:
            NMDevice *getNmDevice();

        private:
            // Private constructor and destructor
            wifiManager() : client(nullptr), loop(nullptr), create(false) {
                loop = g_main_loop_new(NULL, FALSE);
            }
            ~wifiManager() {
                // Clean up
                NMLOG_TRACE("~wifiManager");
                if(client != nullptr)
                    g_object_unref(client);
                if (loop != NULL) {
                    g_main_loop_unref(loop);
                    loop = NULL;  // Set the pointer to NULL to avoid accidental reuse
                }
            }


            // Delete copy constructor and assignment operator
            wifiManager(wifiManager const&) = delete;
            void operator=(wifiManager const&) = delete;

            bool createClientNewConnection();

        public:
            NMClient *client;
            GMainLoop *loop;
            gboolean create;
            const char* specific_object;
            NMDevice *wifidevice;
            guint wifiDeviceStateGsignal = 0;
        };
    }
}
/*
----------------ap flag----------------
NM_802_11_AP_FLAGS_NONE    = 0x00000000,
NM_802_11_AP_FLAGS_PRIVACY = 0x00000001,
NM_802_11_AP_FLAGS_WPS     = 0x00000002,
NM_802_11_AP_FLAGS_WPS_PBC = 0x00000004,
NM_802_11_AP_FLAGS_WPS_PIN = 0x00000008,
-------------------------ap_wpa_flags----------------
NM_802_11_AP_SEC_NONE                     = 0x00000000,
NM_802_11_AP_SEC_PAIR_WEP40               = 0x00000001,
NM_802_11_AP_SEC_PAIR_WEP104              = 0x00000002,
NM_802_11_AP_SEC_PAIR_TKIP                = 0x00000004,
NM_802_11_AP_SEC_PAIR_CCMP                = 0x00000008,
NM_802_11_AP_SEC_GROUP_WEP40              = 0x00000010,
NM_802_11_AP_SEC_GROUP_WEP104             = 0x00000020,
NM_802_11_AP_SEC_GROUP_TKIP               = 0x00000040,
NM_802_11_AP_SEC_GROUP_CCMP               = 0x00000080,
NM_802_11_AP_SEC_KEY_MGMT_PSK             = 0x00000100,
NM_802_11_AP_SEC_KEY_MGMT_802_1X          = 0x00000200,
NM_802_11_AP_SEC_KEY_MGMT_SAE             = 0x00000400,
NM_802_11_AP_SEC_KEY_MGMT_OWE             = 0x00000800,
NM_802_11_AP_SEC_KEY_MGMT_OWE_TM          = 0x00001000,
NM_802_11_AP_SEC_KEY_MGMT_EAP_SUITE_B_192 = 0x00002000,
*/