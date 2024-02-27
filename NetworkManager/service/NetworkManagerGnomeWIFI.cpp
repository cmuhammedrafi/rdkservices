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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <iostream>

#include <glib.h>
#include <NetworkManager.h>
#include <libnm/NetworkManager.h>
#include "NetworkManagerLogger.h"
#include "NetworkManagerGnomeWIFI.h"
#include "NetworkManagerImplementation.h"
#include "INetworkManager.h"

namespace WPEFramework
{
    namespace Plugin
    {

        NMDevice* wifiManager::getNmDevice()
        {
            NMDevice *wifiDevice = NULL;

            GPtrArray *devices = const_cast<GPtrArray *>(nm_client_get_devices(client));
            if (devices == NULL) {
                NMLOG_ERROR("Failed to get device list.");
                return wifiDevice;
            }

            for (guint j = 0; j < devices->len; j++) {
                NMDevice *device = NM_DEVICE(devices->pdata[j]);
                if (nm_device_get_device_type(device) == NM_DEVICE_TYPE_WIFI)
                {
                    wifiDevice = device;
                    //NMLOG_TRACE("Wireless Device found ifce : %s !", nm_device_get_iface (wifiDevice));
                    break;
                }
            }

            if (wifiDevice == NULL || !NM_IS_DEVICE_WIFI(wifiDevice))
            {
                NMLOG_ERROR("Wireless Device not found !");
            }

            return wifiDevice;
        }

        /* Convert flags to string */
        static void apFlagsToString(guint32 flags, std::string &flagStr)
        {

            flagStr = "";

            if (flags & NM_802_11_AP_SEC_PAIR_WEP40)
                flagStr += "pair_wpe40 ";
            if (flags & NM_802_11_AP_SEC_PAIR_WEP104)
                flagStr += "pair_wpe104 ";
            if (flags & NM_802_11_AP_SEC_PAIR_TKIP)
                flagStr += "pair_tkip ";
            if (flags & NM_802_11_AP_SEC_PAIR_CCMP)
                flagStr += "pair_ccmp ";
            if (flags & NM_802_11_AP_SEC_GROUP_WEP40)
                flagStr += "group_wpe40 ";
            if (flags & NM_802_11_AP_SEC_GROUP_WEP104)
                flagStr += "group_wpe104 ";
            if (flags & NM_802_11_AP_SEC_GROUP_TKIP)
                flagStr += "group_tkip ";
            if (flags & NM_802_11_AP_SEC_GROUP_CCMP)
                flagStr += "group_ccmp ";
            if (flags & NM_802_11_AP_SEC_KEY_MGMT_PSK)
                flagStr += "psk ";
            if (flags & NM_802_11_AP_SEC_KEY_MGMT_802_1X)
            flagStr += "802.1X ";
            if (flags & NM_802_11_AP_SEC_KEY_MGMT_SAE)
            flagStr += "sae ";
            if (flags & NM_802_11_AP_SEC_KEY_MGMT_OWE)
                flagStr += "owe " ;
            if (flags & NM_802_11_AP_SEC_KEY_MGMT_OWE_TM)
                flagStr += "owe_transition_mode ";
            if (flags & NM_802_11_AP_SEC_KEY_MGMT_EAP_SUITE_B_192)
                flagStr += "wpa-eap-suite-b-192 ";

            if (flagStr.size() <= 0)
                flagStr = "none";
        }

        static void getApInfo(NMAccessPoint *ap, Exchange::INetworkManager::WiFiSSIDInfo &wifiInfo)
        {
            guint32     flags, wpa_flags, rsn_flags, freq, bitrate;
            guint8      strength;
            GBytes     *ssid;
            const char *hwaddr;
            NM80211Mode mode;
            /* Get AP properties */
            flags     = nm_access_point_get_flags(ap);
            wpa_flags = nm_access_point_get_wpa_flags(ap);
            rsn_flags = nm_access_point_get_rsn_flags(ap);
            ssid      = nm_access_point_get_ssid(ap);
            hwaddr    = nm_access_point_get_bssid(ap);
            freq      = nm_access_point_get_frequency(ap);
            mode      = nm_access_point_get_mode(ap);
            bitrate   = nm_access_point_get_max_bitrate(ap);
            strength  = nm_access_point_get_strength(ap);

            switch(flags)
            {
                case NM_802_11_AP_FLAGS_NONE:
                    NMLOG_INFO("ap type : point has no special capabilities");
                    break;
                case NM_802_11_AP_FLAGS_PRIVACY:
                    NMLOG_INFO("ap type : access point requires authentication and encryption");
                    break;
                case NM_802_11_AP_FLAGS_WPS:
                    NMLOG_INFO("ap type : access point supports some WPS method");
                    break;
                case NM_802_11_AP_FLAGS_WPS_PBC:
                    NMLOG_INFO("ap type : access point supports push-button WPS");
                    break;
                case NM_802_11_AP_FLAGS_WPS_PIN:
                    NMLOG_INFO("ap type : access point supports PIN-based WPS");
                    break;
                default:
                    NMLOG_ERROR("ap type : 802.11 flags unknown!");
            }

            /* Convert to strings */
            if (ssid) {
                gsize size;
                const guint8 *ssidData = static_cast<const guint8 *>(g_bytes_get_data(ssid, &size));
                std::string ssidTmp(reinterpret_cast<const char *>(ssidData), size);
                wifiInfo.m_ssid = ssidTmp;
                NMLOG_INFO("ssid: %s", wifiInfo.m_ssid.c_str());
            }
            else
            {
            wifiInfo.m_ssid = "-----";
            NMLOG_TRACE("ssid: %s", wifiInfo.m_ssid.c_str());
            }

            wifiInfo.m_bssid = (hwaddr != nullptr) ? hwaddr : "-----";
            NMLOG_INFO("bssid: %s", wifiInfo.m_bssid.c_str());


            if (freq >= 2400 && freq < 5000) {
                wifiInfo.m_frequency = Exchange::INetworkManager::WiFiFrequency::WIFI_FREQUENCY_2_4_GHZ;
                NMLOG_INFO("freq: WIFI_FREQUENCY_2_4_GHZ");
            }
            else if (freq >= 5000 && freq < 6000) {
                wifiInfo.m_frequency =  Exchange::INetworkManager::WiFiFrequency::WIFI_FREQUENCY_5_GHZ;
                NMLOG_INFO("freq: WIFI_FREQUENCY_5_GHZ");
            }
            else if (freq >= 6000) {
                wifiInfo.m_frequency = Exchange::INetworkManager::WiFiFrequency::WIFI_FREQUENCY_6_GHZ;
                NMLOG_INFO("freq: WIFI_FREQUENCY_6_GHZ");
            }
            else {
                wifiInfo.m_frequency = Exchange::INetworkManager::WiFiFrequency::WIFI_FREQUENCY_WHATEVER;
                NMLOG_INFO("freq: No available !");
            }

            wifiInfo.m_rate = std::to_string(bitrate);
            NMLOG_INFO("bitrate : %s kbit/s", wifiInfo.m_rate.c_str());

            wifiInfo.m_signalStrength = std::to_string(static_cast<u_int8_t>(strength));
            NMLOG_INFO("sterngth: %s %%", wifiInfo.m_signalStrength.c_str());
            //TODO signal strenght to dBm

            std::string security_str = "";
            if (!(flags & NM_802_11_AP_FLAGS_PRIVACY) && (wpa_flags != NM_802_11_AP_SEC_NONE)
                && (rsn_flags != NM_802_11_AP_SEC_NONE))
                security_str += ("Encrypted: ");

            if ((flags & NM_802_11_AP_FLAGS_PRIVACY) && (wpa_flags == NM_802_11_AP_SEC_NONE)
                && (rsn_flags == NM_802_11_AP_SEC_NONE))
                security_str += ("WEP ");
            if (wpa_flags != NM_802_11_AP_SEC_NONE)
                security_str += ("WPA ");
            if ((rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_PSK)
                || (rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_802_1X)) {
                security_str += ("WPA2 ");
            }
            if (rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_SAE) {
                security_str += ("WPA3 ");
            }
            if ((rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_OWE)
                || (rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_OWE_TM)) {
                security_str += ("OWE ");
            }
            if ((wpa_flags & NM_802_11_AP_SEC_KEY_MGMT_802_1X)
                || (rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_802_1X)) {
                security_str += ("802.1X ");
            }

            NMLOG_INFO("security: %s", (security_str.size() > 0)? security_str.c_str(): "none");
            std::string flagStr;
            apFlagsToString(wpa_flags, flagStr);
            apFlagsToString(rsn_flags, flagStr);
            NMLOG_INFO("WPA flags: %s", flagStr.c_str());
            NMLOG_INFO("RSN flags: %s", flagStr.c_str());
            NMLOG_TRACE("D-Bus path: %s", nm_object_get_path(NM_OBJECT(ap)));
            NMLOG_INFO("Mode: %s", mode == NM_802_11_MODE_ADHOC   ? "Ad-Hoc": mode == NM_802_11_MODE_INFRA ? "Infrastructure": "Unknown");
        }

        bool wifiManager::isWifiConnected()
        {
            if(!createClientNewConnection())
                return false;

            NMDeviceWifi *wifiDevice = NM_DEVICE_WIFI(getNmDevice());
            if(wifiDevice == NULL) {
                NMLOG_TRACE("NMDeviceWifi * NULL !");
                return false;
            }

            NMAccessPoint *activeAP = nm_device_wifi_get_active_access_point(wifiDevice);
            if(activeAP == NULL) {
                NMLOG_ERROR("No active access point found !");
                return false;
            }
            else
                NMLOG_TRACE("active access point found !");
            return true;
        }

        bool wifiManager::wifiConnectedSSIDInfo(Exchange::INetworkManager::WiFiSSIDInfo &ssidinfo)
        {
            if(!createClientNewConnection())
                return false;

            NMDeviceWifi *wifiDevice = NM_DEVICE_WIFI(getNmDevice());
            if(wifiDevice == NULL) {
                NMLOG_TRACE("NMDeviceWifi * NULL !");
                return false;
            }

            NMAccessPoint *activeAP = nm_device_wifi_get_active_access_point(wifiDevice);
            if(activeAP == NULL) {
                NMLOG_ERROR("No active access point found !");
                return false;
            }
            else
                NMLOG_TRACE("active access point found !");

            getApInfo(activeAP, ssidinfo);
            return true;
        }

        static void wifiDisconnectCb(GObject *object, GAsyncResult *result, gpointer user_data)
        {
            NMDevice     *device = NM_DEVICE(object);
            GError       *error = NULL;
            wifiManager *_wifiManager = (static_cast<wifiManager*>(user_data));

            NMLOG_TRACE("Disconnecting... ");
            if (!nm_device_disconnect_finish(device, result, &error)) {
                if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
                    return;

                NMLOG_ERROR("Device '%s' (%s) disconnecting failed: %s",
                            nm_device_get_iface(device),
                            nm_object_get_path(NM_OBJECT(device)),
                            error->message);
                g_error_free(error);
                _wifiManager->quit(device);
            }
        }

        void static disconnectGsignalCb(NMDevice *device, GParamSpec *pspec, wifiManager *info)
        {
            if(NM_IS_DEVICE_WIFI(device))
            {
                NMDeviceState state = nm_device_get_state(device);
                switch(state)
                {
                    case NM_DEVICE_STATE_DEACTIVATING:
                        NMLOG_INFO("Device '%s' successfully disconnecting", nm_device_get_iface(device));
                    break;
                    case NM_DEVICE_STATE_DISCONNECTED:
                        NMLOG_INFO("Device '%s' successfully disconnected", nm_device_get_iface(device));
                        info->quit(device);
                    break;
                    case NM_DEVICE_STATE_ACTIVATED:
                        NMLOG_INFO("Device '%s' successfully connected", nm_device_get_iface(device));
                        info->quit(device);
                    case NM_DEVICE_STATE_FAILED:
                        NMLOG_INFO("Device '%s' Failed state", nm_device_get_iface(device));
                        break;
                    default:
                        NMLOG_TRACE("Device state unknown");
                }
            }
        }

        static void connectGsignalCb(NMDevice *device, GParamSpec *pspec, wifiManager *info)
        {
            if(NM_IS_DEVICE_WIFI(device))
            {
                NMDeviceState state = nm_device_get_state(device);
                switch(state)
                {
                    case NM_DEVICE_STATE_DEACTIVATING:
                        NMLOG_INFO("Device disconnecting");
                    break;
                    case NM_DEVICE_STATE_DISCONNECTED:
                        NMLOG_INFO("Device '%s' successfully disconnected", nm_device_get_iface(device));
                    break;
                    case NM_DEVICE_STATE_ACTIVATED:
                        NMLOG_INFO("Device '%s' successfully connected", nm_device_get_iface(device));
                        info->quit(device);
                    case NM_DEVICE_STATE_FAILED:
                        //NMLOG_INFO("Device '%s' Failed state", nm_device_get_iface(device));
                    default:
                    break;
                }
            }
        }

        bool wifiManager::wifiDisconnect()
        {
            if(!createClientNewConnection())
                return false;

            NMDevice *wifiNMDevice = getNmDevice();
            if(wifiNMDevice == NULL) {
                NMLOG_TRACE("NMDeviceWifi NULL !");
                return false;
            }

            wifiDeviceStateGsignal = g_signal_connect(wifiNMDevice, "notify::" NM_DEVICE_STATE, G_CALLBACK(disconnectGsignalCb), this);
            nm_device_disconnect_async(wifiNMDevice, NULL, wifiDisconnectCb, this);
            wait(loop);
            NMLOG_TRACE("Exit");
            return true;
        }

        bool wifiManager::quit(NMDevice *wifiNMDevice)
        {
            if (wifiNMDevice && wifiDeviceStateGsignal > 0) {
                g_signal_handler_disconnect(wifiNMDevice, wifiDeviceStateGsignal);
                wifiDeviceStateGsignal = 0;
            }

            if(!g_main_loop_is_running(loop)) {
                NMLOG_ERROR("g_main_loop_is not running");
                return false;
            }

            g_main_loop_quit(loop);
            return false;
        }

        bool wifiManager::wait(GMainLoop *loop)
        {
            if(g_main_loop_is_running(loop)) {
                NMLOG_WARNING("g_main_loop_is running");
                return false;
            }
            g_main_loop_run(loop);
            return true;
        }

        static NMAccessPoint *checkSSIDAvailable(NMDevice *device, const GPtrArray *aps, const char *ssid)
        {
            NMAccessPoint   *ap = NULL;
            aps = nm_device_wifi_get_access_points(NM_DEVICE_WIFI(device));
            for (guint i = 0; i < aps->len; i++)
            {
                NMAccessPoint *candidate_ap = static_cast<NMAccessPoint *>(g_ptr_array_index(aps, i));
                if (ssid)
                {
                    GBytes *ssidGBytes;
                    ssidGBytes = nm_access_point_get_ssid(candidate_ap);
                    if (!ssidGBytes)
                        continue;
                    gsize size;
                    const guint8 *ssidData = static_cast<const guint8 *>(g_bytes_get_data(ssidGBytes, &size));
                    std::string ssidstr(reinterpret_cast<const char *>(ssidData), size);
                    //g_bytes_unref(ssidGBytes);
                    NMLOG_TRACE("ssid <  %s  >", ssidstr.c_str());
                    if (strcmp(ssid, ssidstr.c_str()) == 0)
                    {
                        ap = candidate_ap;
                        break;
                    }
                }
            }

            return ap;
        }

        static void wifiConnectCb(GObject *client, GAsyncResult *result, gpointer user_data)
        {
            GError *error = NULL;
            wifiManager *_wifiManager = (static_cast<wifiManager*>(user_data));

            if (_wifiManager->create) {
                NMLOG_TRACE("nm_client_add_and_activate_connection_finish");
                nm_client_add_and_activate_connection_finish(NM_CLIENT(_wifiManager->client), result, &error);
            }
            else {
                NMLOG_TRACE("nm_client_activate_connection_finish ");
                nm_client_activate_connection_finish(NM_CLIENT(_wifiManager->client), result, &error);
            }

            if (error) {
                if (_wifiManager->create) {
                    NMLOG_ERROR("Failed to add/activate new connection: %s", error->message);
                } else {
                    NMLOG_ERROR("Failed to activate connection: %s", error->message);
                }
                g_main_loop_quit(_wifiManager->loop);
            }
        }

        static void wifiConnectionUpdate(GObject *source_object, GAsyncResult *res, gpointer user_data)
        {
            NMRemoteConnection        *remote_con = NM_REMOTE_CONNECTION(source_object);
            wifiManager *_wifiManager = (static_cast<wifiManager*>(user_data));
            GVariant *ret = NULL;
            GError *error = NULL;

            ret = nm_remote_connection_update2_finish(remote_con, res, &error);

            if (!ret) {
                NMLOG_ERROR("Error: %s.", error->message);
                g_error_free(error);
                _wifiManager->quit(NULL);
                return;
            }
            _wifiManager->create = false; // no need to create new connection
            nm_client_activate_connection_async(_wifiManager->client,
                                                NM_CONNECTION(remote_con),
                                                _wifiManager->wifidevice,
                                                _wifiManager->specific_object,
                                                NULL,
                                                wifiConnectCb,
                                                _wifiManager);
        }
        bool wifiManager::createClientNewConnection()
        {
            GError *error = NULL;
            if(client != nullptr)
            {
                g_object_unref(client);
                client = nullptr;
            }

            client = nm_client_new(NULL, &error);
            if (!client || !loop) {
                NMLOG_ERROR("Could not connect to NetworkManager: %s.", error->message);
                g_error_free(error);
                return false;
            }
            return true;
        }

        bool wifiManager::wifiConnect(const char *ssid_in, const char* password_in, Exchange::INetworkManager::WIFISecurityMode security_in)
        {
            NMAccessPoint *ap = NULL;
            GPtrArray *allaps = NULL;
            const char *con_name = ssid_in;
            NMConnection *connection = NULL;
            NMSettingConnection  *s_con;
            NMSettingWireless *s_wireless = NULL;
            NMSettingWirelessSecurity *s_secure = NULL;
            NM80211ApFlags ap_flags;
            NM80211ApSecurityFlags ap_wpa_flags;
            NM80211ApSecurityFlags ap_rsn_flags;
            const char  *ifname     = NULL;
            const GPtrArray  *avail_cons;
            bool name_match = false;
            gboolean wep_passphrase = FALSE;

            if(!createClientNewConnection())
                return false;

            if (strlen(ssid_in) > 32)
            {
                NMLOG_WARNING("ssid length grater than 32");
                return false;
            }

            NMDevice *device = NULL;
            device = getNmDevice();
            if(device == NULL)
                return false;
            wifidevice = device;
            NMLOG_TRACE("Wireless Device found ifce : %s !", ifname = nm_device_get_iface(device));
            ap = checkSSIDAvailable(device, allaps, ssid_in);
            // TODO Scann hidden ssid also for lnf
            if(ap == NULL) {
                NMLOG_WARNING("No network with SSID '%s' found !", ssid_in);
                return false;
            }
            Exchange::INetworkManager::WiFiSSIDInfo apinfo;
            getApInfo(ap, apinfo);

            avail_cons = nm_device_get_available_connections(device);
            for (guint i = 0; i < avail_cons->len; i++) {
                NMConnection *avail_con = static_cast<NMConnection*>(g_ptr_array_index(avail_cons, i));
                const char   *id        = nm_connection_get_id(NM_CONNECTION(avail_con));

                if (con_name) {
                    if (!id || strcmp(id, con_name))
                        continue;

                    name_match = TRUE;
                }

                if (nm_access_point_connection_valid(ap, NM_CONNECTION(avail_con))) {
                    /* ap has been checked against bssid1, bssid2 and the ssid
                    * and now avail_con has been checked against ap.
                    */
                    connection = g_object_ref(avail_con);
                    NMLOG_INFO("Connection '%s' exists !", con_name);
                    break;
                }
            }

            if (name_match && !connection) {
                NMLOG_ERROR("Connection '%s' exists but properties don't match.", con_name);
                //TODO Remove Connection
                return false;
            }

            if (!connection)
            {
                NMLOG_TRACE("creating new connection '%s' .", con_name);
                connection = nm_simple_connection_new();
                if (con_name) {
                    s_con = (NMSettingConnection *) nm_setting_connection_new();
                    nm_connection_add_setting(connection, NM_SETTING(s_con));
                    const char *uuid = nm_utils_uuid_generate();;

                    g_object_set(G_OBJECT(s_con),
                        NM_SETTING_CONNECTION_UUID,
                        uuid,
                        NM_SETTING_CONNECTION_ID,
                        con_name,
                        NM_SETTING_CONNECTION_TYPE,
                        "802-11-wireless",
                        NULL);
                    nm_connection_add_setting(connection, NM_SETTING(s_con));
                }

                s_wireless = (NMSettingWireless *)nm_setting_wireless_new();
                GBytes *ssid = g_bytes_new(ssid_in, strlen(ssid_in));
                g_object_set(G_OBJECT(s_wireless),
                    NM_SETTING_WIRELESS_SSID,
                    ssid,
                    NULL);
                //g_bytes_unref(ssid);
                /* For lnf network need to include
                *
                * 'bssid' parameter is used to restrict the connection only to the BSSID
                *  g_object_set(s_wifi, NM_SETTING_WIRELESS_BSSID, bssid, NULL);
                *  g_object_set(s_wifi, NM_SETTING_WIRELESS_SSID, ssid, NM_SETTING_WIRELESS_HIDDEN, hidden, NULL);
                */
                nm_connection_add_setting(connection, NM_SETTING(s_wireless));
            }

            /* handle password */
            ap_flags     = nm_access_point_get_flags(ap);
            ap_wpa_flags = nm_access_point_get_wpa_flags(ap);
            ap_rsn_flags = nm_access_point_get_rsn_flags(ap);

            // check ap flag ty securti we supporting
            if(ap_flags != NM_802_11_AP_FLAGS_NONE && strlen(password_in) < 1 ) // should be 8 minimium password length is 8 need to confirm
            {
                NMLOG_ERROR("This ap(%s) security need password please add password!", ssid_in);
                return false;
            }

            /* Set password for WEP or WPA-PSK. */
            if ((ap_flags & NM_802_11_AP_FLAGS_PRIVACY)
                || (ap_wpa_flags != NM_802_11_AP_SEC_NONE
                    && !NM_FLAGS_ANY(ap_wpa_flags,
                                    NM_802_11_AP_SEC_KEY_MGMT_OWE | NM_802_11_AP_SEC_KEY_MGMT_OWE_TM))
                || (ap_rsn_flags != NM_802_11_AP_SEC_NONE
                    && !NM_FLAGS_ANY(ap_rsn_flags,
                                    NM_802_11_AP_SEC_KEY_MGMT_OWE | NM_802_11_AP_SEC_KEY_MGMT_OWE_TM))) { // not any enteprice

                std::string flagStr;
                apFlagsToString(ap_wpa_flags, flagStr);
                apFlagsToString(ap_rsn_flags, flagStr);
                NMLOG_INFO("%s ap securtity mode ( %s) supported !", ssid_in, flagStr.c_str());

                if (!password_in) {
                NMLOG_WARNING("password is none");
                return false;
                }

                /* Key management :- "none" (WEP),  "ieee8021x" (Dynamic WEP), "wpa-none" (Ad-Hoc WPA-PSK), "wpa-psk" (infrastructure WPA-PSK), "wpa-eap" (WPA-Enterprise) */
                if (password_in) 
                {
                    s_secure = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new();
                    nm_connection_add_setting(connection, NM_SETTING(s_secure));

                    if (ap_wpa_flags == NM_802_11_AP_SEC_NONE && ap_rsn_flags == NM_802_11_AP_SEC_NONE) {
                        /* WEP */
                        nm_setting_wireless_security_set_wep_key(s_secure, 0, password_in);
                        NMLOG_ERROR("wifi security WEP mode not supported ! need to add wep-key-type");
                        return false;
                        g_object_set(G_OBJECT(s_secure),
                                    NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE,
                                    wep_passphrase ? NM_WEP_KEY_TYPE_PASSPHRASE : NM_WEP_KEY_TYPE_KEY,
                                    NULL);
                    } else if ((ap_wpa_flags & NM_802_11_AP_SEC_KEY_MGMT_PSK)
                            || (ap_rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_PSK)
                            || (ap_rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_SAE)) {
                        /* WPA PSK */
                        g_object_set(G_OBJECT(s_secure), NM_SETTING_WIRELESS_SECURITY_KEY_MGMT,"wpa-psk", NULL);
                        g_object_set(G_OBJECT(s_secure), NM_SETTING_WIRELESS_SECURITY_PSK, password_in, NULL);
                    }
                }
                else {
                NMLOG_ERROR("This ap(%s) need password please add password!", ssid_in);
                return false;
                }
            }
            else
            {
                /* for open network every flag value will be zero */
                if (ap_flags == NM_802_11_AP_FLAGS_NONE && ap_wpa_flags == NM_802_11_AP_SEC_NONE && ap_rsn_flags == NM_802_11_AP_SEC_NONE) {
                    NMLOG_INFO("open network no password requied");
                }
                else {
                    NMLOG_ERROR("wifi security mode not supported !");
                    return false;
                }
            }

            specific_object = nm_object_get_path(NM_OBJECT(ap));
            wifiDeviceStateGsignal = g_signal_connect(device, "notify::" NM_DEVICE_STATE, G_CALLBACK(connectGsignalCb), this);

            if (NM_IS_REMOTE_CONNECTION(connection)) {
                nm_remote_connection_update2(NM_REMOTE_CONNECTION(connection),
                                            nm_connection_to_dbus(connection, NM_CONNECTION_SERIALIZE_ALL),
                                            NM_SETTINGS_UPDATE2_FLAG_BLOCK_AUTOCONNECT, // autoconnect right away
                                            NULL,
                                            NULL,
                                            wifiConnectionUpdate,
                                            this);
            }
            else
            {
                create = true;
                nm_client_add_and_activate_connection_async(client,
                                                                connection,
                                                                device,
                                                                specific_object,
                                                                NULL,
                                                                wifiConnectCb,
                                                                this);
            }

            wait(loop);
            NMLOG_TRACE("Exit");
            return true;
        }
    } // namespace Plugin
} // namespace WPEFramework
