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
static void ap_wpa_rsn_flags_to_string(guint32 flags, std::string &flagStr)
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

static void getNMAccessPointData(NMAccessPoint *ap, Exchange::INetworkManager::WiFiSSIDInfo &wifiInfo)
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
            NMLOG_INFO("ap type : access point requires authentication and encryption(WEP)");
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
    ap_wpa_rsn_flags_to_string(wpa_flags, flagStr);
    ap_wpa_rsn_flags_to_string(rsn_flags, flagStr);
    NMLOG_INFO("WPA flags: %s", flagStr.c_str());
    NMLOG_INFO("RSN flags: %s", flagStr.c_str());
    NMLOG_TRACE("D-Bus path: %s", nm_object_get_path(NM_OBJECT(ap)));
    NMLOG_INFO("Mode: %s", mode == NM_802_11_MODE_ADHOC   ? "Ad-Hoc": mode == NM_802_11_MODE_INFRA ? "Infrastructure": "Unknown");
}

bool wifiManager::isWifiConnected()
{
    Exchange::INetworkManager::WiFiSSIDInfo ssidinfo;
    return wifiConnectedSSIDInfo(ssidinfo);
}

bool wifiManager::wifiConnectedSSIDInfo(Exchange::INetworkManager::WiFiSSIDInfo &ssidinfo)
{
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

    getNMAccessPointData(activeAP, ssidinfo);
    return true;
}

void wifiManager::wifiDisconnectCb(GObject *object, GAsyncResult *result, gpointer user_data)
{
    NMDevice     *device = NM_DEVICE(object);
    GError       *error = NULL;
    wifiManager *_wifiManager = (static_cast<wifiManager*>(user_data));

    printf("disconnecting... ");
    if (!nm_device_disconnect_finish(device, result, &error)) {
        if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
            return;

        NMLOG_ERROR("Error: Device '%s' (%s) disconnecting failed: %s",
                     nm_device_get_iface(device),
                     nm_object_get_path(NM_OBJECT(device)),
                     error->message);
        g_error_free(error);
        _wifiManager->quit(device);
    }
    NMLOG_INFO("Device disconnecting....");
}

void wifiManager::disconnectGsignalCb(NMDevice *device, GParamSpec *pspec, wifiManager *info)
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

void wifiManager::connectGsignalCb(NMDevice *device, GParamSpec *pspec, wifiManager *info)
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
    if(!client) {
        NMLOG_ERROR("NMClient NULL");
        return false;
    }

    NMDevice *wifiNMDevice = getNmDevice();
    if(wifiNMDevice == NULL) {
        NMLOG_TRACE("NMDeviceWifiNULL !");
        return false;
    }

    wifiDeviceStateGsignal = g_signal_connect(wifiNMDevice, "notify::" NM_DEVICE_STATE, G_CALLBACK(disconnectGsignalCb), this);
    nm_device_disconnect_async(wifiNMDevice, NULL, wifiDisconnectCb, this);
    return true;
}

bool wifiManager::quit(NMDevice *wifiNMDevice)
{
     NMLOG_INFO("Exit");
    if(!g_main_loop_is_running(loop)) {
        NMLOG_ERROR("g_main_loop_is not running");
        return false;
    }

    if (wifiNMDevice && wifiDeviceStateGsignal > 0) {
        g_signal_handler_disconnect(wifiNMDevice, wifiDeviceStateGsignal);
        wifiDeviceStateGsignal = 0;
    }

    g_main_loop_quit(loop);
    return false;
}

gboolean wifiManager::nm_clear_g_cancellable(GCancellable **cancellable)
{
    GCancellable *v;

    if (cancellable && (v = *cancellable)) {
        *cancellable = NULL;
        g_cancellable_cancel(v);
        g_object_unref(v);
        return TRUE;
    }
    return FALSE;
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

void wifiManager::wifiConnectCb(GObject *client, GAsyncResult *result, gpointer user_data)
{
    GError *error = NULL;
    wifiManager *_wifiManager = (static_cast<wifiManager*>(user_data));

    if (_wifiManager->create) {
        NMLOG_TRACE("nm_client_add_and_activate_connection_finish");
        nm_client_add_and_activate_connection_finish(NM_CLIENT(_wifiManager->client), result, &error);
        //_wifiManager->quit(NULL);
    }
    else {
        NMLOG_TRACE("nm_client_activate_connection_finish ");
        nm_client_activate_connection_finish(NM_CLIENT(_wifiManager->client), result, &error);
    }

    if (error) {
        if (_wifiManager->create) {
            NMLOG_ERROR("Error: Failed to add/activate new connection: %s", error->message);
        } else {
            NMLOG_ERROR("Error: Failed to activate connection: %s", error->message);
        }
        g_main_loop_quit(_wifiManager->loop);
    }
}

bool wifiManager::wifiConnect(const char *ssid_in, const char* password_in, Exchange::INetworkManager::WIFISecurityMode security_in)
{
    NMRemoteConnection *rem_con = NULL;
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
    // TODO added feature
    gboolean wep_passphrase = FALSE;

    rem_con = nm_client_get_connection_by_id(client, con_name);
    if(rem_con != NULL)
    {
        NMLOG_WARNING("old connection found not supporting this configuration");
    }

    NMDevice *device = NULL;
    device = getNmDevice();
    if(device == NULL)
        return false;
    ap = checkSSIDAvailable(device, allaps, ssid_in);

    if(ap == NULL) {
        NMLOG_WARNING("No network with SSID '%s' found !", ssid_in);
        return false;
    }
    Exchange::INetworkManager::WiFiSSIDInfo apinfo;
    getNMAccessPointData(ap, apinfo);

    if (!connection)
    {
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
        /* 'bssid' parameter is used to restrict the connection only to the BSSID */
        // g_object_set(s_wifi, NM_SETTING_WIRELESS_BSSID, bssid, NULL);

        nm_connection_add_setting(connection, NM_SETTING(s_wireless));
        // g_object_set(s_wifi,
        //                 NM_SETTING_WIRELESS_SSID,
        //                 ssid,
        //                 NM_SETTING_WIRELESS_HIDDEN,
        //                 hidden,
        //                 NULL);

    }

    /* handle password */
    ap_flags     = nm_access_point_get_flags(ap);
    ap_wpa_flags = nm_access_point_get_wpa_flags(ap);
    ap_rsn_flags = nm_access_point_get_rsn_flags(ap);

    // check ap flag ty securti we supporting

    /* Set password for WEP or WPA-PSK. */
    if ((ap_flags & NM_802_11_AP_FLAGS_PRIVACY)
        || (ap_wpa_flags != NM_802_11_AP_SEC_NONE
            && !NM_FLAGS_ANY(ap_wpa_flags,
                             NM_802_11_AP_SEC_KEY_MGMT_OWE | NM_802_11_AP_SEC_KEY_MGMT_OWE_TM))
        || (ap_rsn_flags != NM_802_11_AP_SEC_NONE
            && !NM_FLAGS_ANY(ap_rsn_flags,
                             NM_802_11_AP_SEC_KEY_MGMT_OWE | NM_802_11_AP_SEC_KEY_MGMT_OWE_TM))) {
        const char                *con_password = NULL;

        NMLOG_TRACE("%s ap securtity mode supported !", ssid_in);

        if (!password_in && !con_password ) {
           NMLOG_WARNING("password is none");
        }

        /* Key management :- "none" (WEP),  "ieee8021x" (Dynamic WEP), "wpa-none" (Ad-Hoc WPA-PSK), "wpa-psk" (infrastructure WPA-PSK), "wpa-eap" (WPA-Enterprise) */
        if (password_in) 
        {
            if (!s_secure) {
                s_secure = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new();
                nm_connection_add_setting(connection, NM_SETTING(s_secure));
            }

            if (ap_wpa_flags == NM_802_11_AP_SEC_NONE && ap_rsn_flags == NM_802_11_AP_SEC_NONE) {
                /* WEP */
                nm_setting_wireless_security_set_wep_key(s_secure, 0, password_in);
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
        else
           NMLOG_ERROR("This ap(%s) need password please add password!", ssid_in);
    }
    else
    {
        /* for open network every flag value will be zero */
        if (ap_flags == NM_802_11_AP_FLAGS_NONE && ap_wpa_flags == NM_802_11_AP_SEC_NONE && ap_rsn_flags == NM_802_11_AP_SEC_NONE) {
            NMLOG_INFO("open network no password requied");
            s_secure = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new();
            g_object_set(G_OBJECT(s_secure), NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "none", NULL);
            nm_connection_add_setting(connection, NM_SETTING(s_secure));
        }
        else {
            NMLOG_ERROR("This ap(%s) need password please add password!", ssid_in);
            return false;
        }
    }

    create = true;
    wifiDeviceStateGsignal = g_signal_connect(device, "notify::" NM_DEVICE_STATE, G_CALLBACK(connectGsignalCb), this);
    nm_client_add_and_activate_connection_async(client,
                                                    connection,
                                                    device,
                                                    nm_object_get_path(NM_OBJECT(ap)),
                                                    NULL,
                                                    wifiConnectCb,
                                                    this);

    NMLOG_TRACE("Exit");
    return true;
}

    } // namespace Plugin
} // namespace WPEFramework