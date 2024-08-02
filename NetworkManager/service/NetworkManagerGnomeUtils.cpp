#include <stdlib.h>
#include <stdio.h>
#include <glib.h>
#include <thread>
#include <string>
#include <map>
#include <NetworkManager.h>
#include <libnm/NetworkManager.h>
#include "Module.h"
#include "NetworkManagerGnomeEvents.h"
#include "NetworkManagerLogger.h"
#include "NetworkManagerGnomeUtils.h"
#include "NetworkManagerImplementation.h"
#include "INetworkManager.h"

namespace WPEFramework
{
    namespace Plugin
    {
       uint8_t nmUtils::wifiSecurityModeFromAp(guint32 flags, guint32 wpaFlags, guint32 rsnFlags)
       {
            uint8_t security = Exchange::INetworkManager::WIFI_SECURITY_NONE;
            if ((flags == NM_802_11_AP_FLAGS_NONE) && (wpaFlags == NM_802_11_AP_SEC_NONE) && (rsnFlags == NM_802_11_AP_SEC_NONE))
            {
                security = Exchange::INetworkManager::WIFISecurityMode::WIFI_SECURITY_NONE;
            }
            else if( (flags & NM_802_11_AP_FLAGS_PRIVACY) && ((wpaFlags & NM_802_11_AP_SEC_PAIR_WEP40) || (rsnFlags & NM_802_11_AP_SEC_PAIR_WEP40)) )
            {
                security = Exchange::INetworkManager::WIFISecurityMode::WIFI_SECURITY_WEP_64;
            }
            else if( (flags & NM_802_11_AP_FLAGS_PRIVACY) && ((wpaFlags & NM_802_11_AP_SEC_PAIR_WEP104) || (rsnFlags & NM_802_11_AP_SEC_PAIR_WEP104)) )
            {
                security = Exchange::INetworkManager::WIFISecurityMode::WIFI_SECURITY_WEP_128;
            }
            else if((wpaFlags & NM_802_11_AP_SEC_PAIR_TKIP) || (rsnFlags & NM_802_11_AP_SEC_PAIR_TKIP))
            {
                security = Exchange::INetworkManager::WIFISecurityMode::WIFI_SECURITY_WPA_PSK_TKIP;
            }
            else if((wpaFlags & NM_802_11_AP_SEC_PAIR_CCMP) || (rsnFlags & NM_802_11_AP_SEC_PAIR_CCMP))
            {
                security = Exchange::INetworkManager::WIFISecurityMode::WIFI_SECURITY_WPA_PSK_AES;
            }
            else if ((rsnFlags & NM_802_11_AP_SEC_KEY_MGMT_PSK) && (rsnFlags & NM_802_11_AP_SEC_KEY_MGMT_802_1X))
            {
                security = Exchange::INetworkManager::WIFISecurityMode::WIFI_SECURITY_WPA_WPA2_ENTERPRISE;
            }
            else if(rsnFlags & NM_802_11_AP_SEC_KEY_MGMT_PSK)
            {
                security = Exchange::INetworkManager::WIFISecurityMode::WIFI_SECURITY_WPA_WPA2_PSK;
            }
            else if((wpaFlags & NM_802_11_AP_SEC_GROUP_CCMP) || (rsnFlags & NM_802_11_AP_SEC_GROUP_CCMP))
            {
                security = Exchange::INetworkManager::WIFISecurityMode::WIFI_SECURITY_WPA2_PSK_AES;
            }
            else if((wpaFlags & NM_802_11_AP_SEC_GROUP_TKIP) || (rsnFlags & NM_802_11_AP_SEC_GROUP_TKIP))
            {
                security = Exchange::INetworkManager::WIFISecurityMode::WIFI_SECURITY_WPA2_PSK_TKIP;
            }
            else if((rsnFlags & NM_802_11_AP_SEC_KEY_MGMT_OWE) || (rsnFlags & NM_802_11_AP_SEC_KEY_MGMT_OWE_TM))
            {
                security = Exchange::INetworkManager::WIFISecurityMode::WIFI_SECURITY_WPA3_SAE;
            }
            else
                NMLOG_WARNING("security mode not defined (flag: %d, wpaFlags: %d, rsnFlags: %d)", flags, wpaFlags, rsnFlags);
            return security;
       }

       std::string nmUtils::wifiFrequencyFromAp(guint32 apFreq)
       {
            std:string freq;
            if (apFreq >= 2400 && apFreq < 5000)
                freq = "2.4";
            else if (apFreq >= 5000 && apFreq < 6000)
                freq = "5";
            else if (apFreq >= 6000)
                freq = "6";
            else
                freq = "Not available";

            return freq;
       }

       JsonObject nmUtils::apToJsonObject(NMAccessPoint *ap)
       {
            GError *error = NULL;
            GBytes *ssid = NULL;
            int strength = 0;
            std::string freq;
            int security;
            guint32 flags, wpaFlags, rsnFlags, apFreq;
            JsonObject ssidObj;
            if(ap == nullptr)
                return ssidObj;
            ssid = nm_access_point_get_ssid(ap);
            if (ssid)
            {
                char *ssidStr = nullptr;
                ssidStr = nm_utils_ssid_to_utf8((const guint8*)g_bytes_get_data(ssid, NULL), g_bytes_get_size(ssid));
                string ssidString(ssidStr);
                ssidObj["ssid"] = ssidString;
            }
            else
                ssidObj["ssid"] = "---"; // hidden ssid TODO modify
            strength = nm_access_point_get_strength(ap);
            apFreq   = nm_access_point_get_frequency(ap);
            flags    = nm_access_point_get_flags(ap);
            wpaFlags = nm_access_point_get_wpa_flags(ap);
            rsnFlags = nm_access_point_get_rsn_flags(ap);
            freq = nmUtils::wifiFrequencyFromAp(apFreq);
            security = nmUtils::wifiSecurityModeFromAp(flags, wpaFlags, rsnFlags);

            ssidObj["security"] = security;
            ssidObj["signalStrength"] = strength;
            ssidObj["frequency"] = freq;

            return ssidObj;
       }
    }   // Plugin
}   // WPEFramework
