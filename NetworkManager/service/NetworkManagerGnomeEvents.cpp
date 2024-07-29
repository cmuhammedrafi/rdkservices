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

#include <glib.h>
#include <thread>
#include <string>
#include <map>

#include <NetworkManager.h>
#include <libnm/NetworkManager.h>
#include "NetworkManagerGnomeEvents.h"
#include "NetworkManagerLogger.h"

static GnomeNetworkManagerEvents *_nmEventInstance = nullptr;

const char* ifnameEth = "enx207bd51e02ad";
const char* ifnameWlan = "wlp0s20f3";

static void primaryConnectionCb(NMClient *client, GParamSpec *param, NMEvents *nmEvents)
{
    NMActiveConnection *primaryConn;
    const char *activeConnId = NULL;
    const char *connectionTyp = NULL;
    primaryConn = nm_client_get_primary_connection(client);
    nmEvents->activeConn = primaryConn;
    if (primaryConn)
    {
        activeConnId = nm_active_connection_get_id(primaryConn);
        connectionTyp = nm_active_connection_get_connection_type(primaryConn);
        NMLOG_INFO("active connection - %s (%s)", activeConnId, connectionTyp);
        std::string newIface ="";

        if (0 == strncmp("802-3-ethernet", connectionTyp, sizeof("802-3-ethernet")))
            newIface = "eth0";
        else if(0 == strncmp("802-11-wireless", connectionTyp, sizeof("802-11-wireless")))
            newIface = "wlan0";
        else
            NMLOG_WARNING("active connection not an ethernet/wifi %s", connectionTyp);

        GnomeNetworkManagerEvents::onActiveInterfaceChangeCb(newIface);
    }
    else
        NMLOG_ERROR("now there's no active connection");
}

static void deviceStateChangeCb(NMDevice *device, GParamSpec *pspec, NMEvents *nmEvents)
{
    NMDeviceState deviceState;
    deviceState = nm_device_get_state(device);
    std::string ifname = nm_device_get_iface(device);
    const char  *nm_device_get_ip_iface(NMDevice *device);
    NMDeviceStateReason reason = nm_device_get_state_reason(device);
    if(ifname == nmEvents->ifnameWlan0)
    {
        std::string wifiState;
        switch (reason)
        {
            case NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE:
                GnomeNetworkManagerEvents::onWIFIStateChanged(0);
                break;
            case NM_DEVICE_STATE_REASON_SSID_NOT_FOUND:
                GnomeNetworkManagerEvents::onWIFIStateChanged(6);
                break;
            // TODO Correct the state number
            case NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT:         // supplicant took too long to authenticate
                GnomeNetworkManagerEvents::onWIFIStateChanged(12);
                break;
            case NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED:          //  802.1x supplicant failed
                GnomeNetworkManagerEvents::onWIFIStateChanged(13);
                break;
            case NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED:   // 802.1x supplicant configuration failed
                GnomeNetworkManagerEvents::onWIFIStateChanged(11);
                break;
            case NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT:      // 802.1x supplicant disconnected
                GnomeNetworkManagerEvents::onWIFIStateChanged(2);
                break;
            default:
            {
                switch (deviceState)
                {
                case NM_DEVICE_STATE_UNKNOWN:
                    wifiState = "WIFI_STATE_UNINSTALLED";
                    GnomeNetworkManagerEvents::onWIFIStateChanged(0);
                    break;
                case NM_DEVICE_STATE_UNMANAGED:
                    wifiState = "WIFI_STATE_DISABLED";
                    GnomeNetworkManagerEvents::onWIFIStateChanged(0);
                    break;
                case NM_DEVICE_STATE_UNAVAILABLE:
                case NM_DEVICE_STATE_DISCONNECTED:
                    wifiState = "WIFI_STATE_DISCONNECTED";
                    GnomeNetworkManagerEvents::onConnectionStatusChangedCb(ifname, false);
                    GnomeNetworkManagerEvents::onWIFIStateChanged(2);
                    break;
                case NM_DEVICE_STATE_PREPARE:
                    wifiState = "WIFI_STATE_PAIRING";
                    GnomeNetworkManagerEvents::onWIFIStateChanged(3);
                    break;
                case NM_DEVICE_STATE_CONFIG:
                    wifiState = "WIFI_STATE_CONNECTING";
                    GnomeNetworkManagerEvents::onWIFIStateChanged(4);
                    break;
                case NM_DEVICE_STATE_IP_CONFIG:
                    break;
                case NM_DEVICE_STATE_ACTIVATED:
                    wifiState = "WIFI_STATE_CONNECTED";
                    GnomeNetworkManagerEvents::onConnectionStatusChangedCb(ifname, true);
                    GnomeNetworkManagerEvents::onWIFIStateChanged(5);
                    break;
                case NM_DEVICE_STATE_DEACTIVATING:
                    wifiState = "WIFI_STATE_CONNECTION_LOST";
                    GnomeNetworkManagerEvents::onWIFIStateChanged(8);
                    break;
                case NM_DEVICE_STATE_FAILED:
                    GnomeNetworkManagerEvents::onWIFIStateChanged(9);
                    wifiState = "WIFI_STATE_CONNECTION_FAILED";
                    break;
                case NM_DEVICE_STATE_NEED_AUTH:
                    GnomeNetworkManagerEvents::onWIFIStateChanged(10);
                    wifiState = "WIFI_STATE_CONNECTION_INTERRUPTED";
                    break;
                default:
                    wifiState = "";
                }
            }
        }
        NMLOG_INFO("wifi state: %s", wifiState.c_str());
    }
    else if(ifname == nmEvents->ifnameEth0)
    {
        switch (deviceState)
        {
            case NM_DEVICE_STATE_UNKNOWN:
            case NM_DEVICE_STATE_UNMANAGED:
                GnomeNetworkManagerEvents::onInterfaceStateChangeCb("eth0", "INTERFACE_DISABLED");
            break;
            case NM_DEVICE_STATE_UNAVAILABLE:
            case NM_DEVICE_STATE_DISCONNECTED:
                GnomeNetworkManagerEvents::onConnectionStatusChangedCb("eth0", false);
                GnomeNetworkManagerEvents::onInterfaceStateChangeCb("eth0", "INTERFACE_LINK_DOWN");
            break;
            case NM_DEVICE_STATE_PREPARE:
                GnomeNetworkManagerEvents::onConnectionStatusChangedCb("eth0", true);
                GnomeNetworkManagerEvents::onInterfaceStateChangeCb("eth0", "INTERFACE_LINK_UP");
            break;
            case NM_DEVICE_STATE_IP_CONFIG:
                GnomeNetworkManagerEvents::onInterfaceStateChangeCb("eth0", "INTERFACE_ACQUIRING_IP");
            case NM_DEVICE_STATE_NEED_AUTH:
            case NM_DEVICE_STATE_SECONDARIES:
            case NM_DEVICE_STATE_ACTIVATED:
            case NM_DEVICE_STATE_DEACTIVATING:
            default:
                NMLOG_WARNING("Unhandiled state change");
        }
    }

    NMLOG_INFO("%s state: (%d)", ifname.c_str(), deviceState);

}

static void ip4ChangedCb(NMIPConfig *ipConfig, GParamSpec *pspec, gpointer userData)
{
    if (!ipConfig) {
        NMLOG_ERROR("IP config is null");
        return;
    }

    NMDevice *device = (NMDevice*)userData;
    if((device == NULL) || (!NM_IS_DEVICE(device)))
       return;

    const char* iface = nm_device_get_iface(device);
    if(iface == NULL)
        return;
    std::string ifname = iface;

    GPtrArray *addresses = nm_ip_config_get_addresses(ipConfig);
    if (!addresses) {
        NMLOG_ERROR("No addresses found");
        return;
    }
    else {
        if(addresses->len == 0) {
            GnomeNetworkManagerEvents::onAddressChangeCb(ifname, "", false, false);
            return;
        }
    }

    for (guint i = 0; i < addresses->len; ++i) {
        NMIPAddress *address = (NMIPAddress *)g_ptr_array_index(addresses, i);
        if (nm_ip_address_get_family(address) == AF_INET) {
            const char *ipAddress = nm_ip_address_get_address(address);
            if(ipAddress != NULL)
                 GnomeNetworkManagerEvents::onAddressChangeCb(iface, ipAddress, true, false);
        }
    }
}

static void ip6ChangedCb(NMIPConfig *ipConfig, GParamSpec *pspec, gpointer userData)
{
    if (!ipConfig) {
        NMLOG_ERROR("ip config is null");
        return;
    }

    NMDevice *device = (NMDevice*)userData;
    if( ((device != NULL) && NM_IS_DEVICE(device)) )
    {
        const char* iface = nm_device_get_iface(device);
        if(iface == NULL)
            return;
        std::string ifname = iface;
        GPtrArray *addresses = nm_ip_config_get_addresses(ipConfig);
        if (!addresses) {
            NMLOG_ERROR("No addresses found");
            return;
        }
        else {
            if(addresses->len == 0) {
                GnomeNetworkManagerEvents::onAddressChangeCb(ifname, "", false, true);
                return;
            }
        }

        for (guint i = 0; i < addresses->len; ++i) {
            NMIPAddress *address = (NMIPAddress *)g_ptr_array_index(addresses, i);
            if (nm_ip_address_get_family(address) == AF_INET6) {
                const char *ipAddress = nm_ip_address_get_address(address);
                //int prefix = nm_ip_address_get_prefix(address);
                if(ipAddress != NULL) {
                    GnomeNetworkManagerEvents::onAddressChangeCb(iface, ipAddress, true, true);
                }
            }
        }
    }
}

static void deviceAddedCB(NMClient *client, NMDevice *device, NMEvents *nmEvents)
{
    if( ((device != NULL) && NM_IS_DEVICE(device)) )
    {
        std::string ifname = nm_device_get_iface(device);
        if(ifname == nmEvents->ifnameWlan0) {
            GnomeNetworkManagerEvents::onInterfaceStateChangeCb("wlan0", "INTERFACE_ADDED");
            GnomeNetworkManagerEvents::onInterfaceStatusChangedCb("wlan0", true);
        }
        else if(ifname == nmEvents->ifnameEth0) {
            GnomeNetworkManagerEvents::onInterfaceStateChangeCb("eth0", "INTERFACE_ADDED");
            GnomeNetworkManagerEvents::onInterfaceStatusChangedCb("eth0", true);
        }
        else {
            GnomeNetworkManagerEvents::onInterfaceStateChangeCb(ifname, "INTERFACE_ADDED");
            GnomeNetworkManagerEvents::onInterfaceStatusChangedCb("ifname", true);
        }
        /* ip events added only for eth0 and wlan0 */
        if((ifname == nmEvents->ifnameEth0) || (ifname == nmEvents->ifnameWlan0))
        {
            g_signal_connect(device, "notify::" NM_DEVICE_STATE, G_CALLBACK(deviceStateChangeCb), nmEvents);
            // TODO call notify::" NM_DEVICE_ACTIVE_CONNECTION if needed
            NMIPConfig *ipv4Config = nm_device_get_ip4_config(device);
            NMIPConfig *ipv6Config = nm_device_get_ip6_config(device);
            if (ipv4Config) {
                g_signal_connect(ipv4Config, "notify::addresses", G_CALLBACK(ip4ChangedCb), device);
            }

            if (ipv6Config) {
                g_signal_connect(ipv6Config, "notify::addresses", G_CALLBACK(ip6ChangedCb), device);
            }
        }
    }
    else
        NMLOG_TRACE("device error null");
} 

static void deviceRemovedCB(NMClient *client, NMDevice *device, NMEvents *nmEvents)
{
    if( ((device != NULL) && NM_IS_DEVICE(device)) )
    {
        std::string ifname = nm_device_get_iface(device);
        if(ifname == nmEvents->ifnameWlan0) {
            GnomeNetworkManagerEvents::onInterfaceStateChangeCb("wlan0", "INTERFACE_REMOVED");
            GnomeNetworkManagerEvents::onInterfaceStatusChangedCb("wlan0", false);
            g_signal_handlers_disconnect_by_func(device, (gpointer)deviceStateChangeCb, nmEvents);
        }
        else if(ifname == nmEvents->ifnameEth0) {
            GnomeNetworkManagerEvents::onInterfaceStateChangeCb("eth0", "INTERFACE_REMOVED");
            GnomeNetworkManagerEvents::onInterfaceStatusChangedCb("eth0", false);
            g_signal_handlers_disconnect_by_func(device, (gpointer)deviceStateChangeCb, nmEvents);
        }
        else {
            GnomeNetworkManagerEvents::onInterfaceStateChangeCb(ifname, "INTERFACE_REMOVED");
            GnomeNetworkManagerEvents::onInterfaceStatusChangedCb(ifname, false);
        }
    }

    //     guint disconnected_count = g_signal_handlers_disconnect_matched( _nmEventInstance->activeConn,
    //                                                                     G_SIGNAL_MATCH_FUNC,
    //                                                                     0, 0, NULL,
    //                                                                     (gpointer)onActiveConnectionStateChanged,
    //                                                                     NULL );
    //     NMLOG_ERROR("Disconnected %u signal handlers\n", disconnected_count);

}

void* GnomeNetworkManagerEvents::networkMangerEventMonitor(void *arg)
{
    if(arg == nullptr)
    {
        NMLOG_FATAL("function argument error: nm event monitor failed");
        return nullptr;
    }

    NMEvents *nmEvents = static_cast<NMEvents *>(arg);
    primaryConnectionCb(nmEvents->client, NULL, nmEvents);
    g_signal_connect(nmEvents->client, "notify::" NM_CLIENT_PRIMARY_CONNECTION, G_CALLBACK(primaryConnectionCb), nmEvents);

    const GPtrArray *devices = nullptr;
    devices = nm_client_get_devices(nmEvents->client);

    g_signal_connect(nmEvents->client, NM_CLIENT_DEVICE_ADDED, G_CALLBACK(deviceAddedCB), nmEvents);
    g_signal_connect(nmEvents->client, NM_CLIENT_DEVICE_REMOVED, G_CALLBACK(deviceRemovedCB), nmEvents);

    for (u_int count = 0; count < devices->len; count++)
    {
        NMDevice *device = NM_DEVICE(g_ptr_array_index(devices, count));
        if( ((device != NULL) && NM_IS_DEVICE(device)) )
        {
            g_signal_connect(device, "notify::" NM_DEVICE_STATE, G_CALLBACK(deviceStateChangeCb), nmEvents);
            //g_signal_connect(device, "notify::" NM_DEVICE_ACTIVE_CONNECTION, G_CALLBACK(deviceActiveConnChangeCb), NULL);
            std::string ifname = nm_device_get_iface(device);
            if((ifname == nmEvents->ifnameEth0) || (ifname == nmEvents->ifnameWlan0)) /* ip events added only for eth0 and wlan0 */
            {
                NMIPConfig *ipv4Config = nm_device_get_ip4_config(device);
                NMIPConfig *ipv6Config = nm_device_get_ip6_config(device);
                if (ipv4Config) {
                    g_signal_connect(ipv4Config, "notify::addresses", G_CALLBACK(ip4ChangedCb), device);
                }

                if (ipv6Config) {
                    g_signal_connect(ipv6Config, "notify::addresses", G_CALLBACK(ip6ChangedCb), device);
                }

                if(NM_IS_DEVICE_WIFI(device)) {
                    nmEvents->wifiDevice = NM_DEVICE_WIFI(device);
                    g_signal_connect(nmEvents->wifiDevice, "notify::" NM_DEVICE_WIFI_LAST_SCAN, G_CALLBACK(GnomeNetworkManagerEvents::onAvailableSSIDsCb), nmEvents);
                }
            }
            else
                NMLOG_TRACE("device type not eth/wifi");
        }
    }

    g_main_loop_run(nmEvents->loop);
    g_main_loop_unref(nmEvents->loop);
    NMLOG_INFO("Register all dbus events");
    return nullptr;
}

bool GnomeNetworkManagerEvents::startNetworkMangerEventMonitor()
{
    if (NULL == nmEvents.client) {
        NMLOG_ERROR("Client Connection NULL DBUS event Failed!");
        return false;
    }

    if(!isEventThrdActive) {
        isEventThrdActive = true;
        // Create event monitor thread
        eventThrdID = g_thread_new("nm_event_thrd", GnomeNetworkManagerEvents::networkMangerEventMonitor, &nmEvents);
    }
    return true;
}

void GnomeNetworkManagerEvents::stopNetworkMangerEventMonitor()
{
   // g_signal_handlers_disconnect_by_func(client, G_CALLBACK(primaryConnectionCb), NULL);
   g_main_loop_quit(nmEvents.loop);
   g_thread_join(eventThrdID);
   isEventThrdActive = false;
   NMLOG_INFO("un registering event handelers");
}

GnomeNetworkManagerEvents::~GnomeNetworkManagerEvents()
{
    NMLOG_TRACE("~GnomeNetworkManagerEvents");
    stopNetworkMangerEventMonitor();
    if(nmEvents.client != nullptr)
        g_object_unref(nmEvents.client);
    if (nmEvents.loop != NULL) {
        g_main_loop_unref(nmEvents.loop);
        nmEvents.loop = NULL;
    }
}

GnomeNetworkManagerEvents::GnomeNetworkManagerEvents()
{
    GError *error = NULL;
    nmEvents.client = nm_client_new(NULL, &error);

    if(!nmEvents.client || error )
    {
        if (error) {
            NMLOG_ERROR("Could not connect to NetworkManager: %s", error->message);
            g_error_free(error);
        }
        NMLOG_INFO("networkmanger client connection failed");
        return;
    }

    NMLOG_INFO("networkmanger client connection success");

    nmEvents.loop = g_main_loop_new(NULL, FALSE);
    if(nmEvents.loop == NULL) {
        NMLOG_FATAL("GMain loop failed! Fatal Error: Event will not work");
        return;
    }
    _nmEventInstance = this;

    nmEvents.ifnameEth0 = "eth0";
    nmEvents.ifnameWlan0 = "wlp0s20f3";
}

/* Gnome networkmanger new events */

void GnomeNetworkManagerEvents::onActiveInterfaceChangeCb(std::string newIface)
{
    static std::string oldIface = "unknown";

    if(oldIface != newIface)
    {
        oldIface = newIface;
        NMLOG_INFO("old interface - %s new interface - %s", oldIface.c_str(), newIface.c_str());
        //TODO call NetworkManager implimation function
    }
}

void GnomeNetworkManagerEvents::onInterfaceStateChangeCb(std::string iface, std::string newState)
{
    static std::string oldState = "unknown";
   // if(oldState != newState)
    {
        oldState = newState;
        NMLOG_INFO("%s interface state changed - %s", iface.c_str(), newState.c_str());
        //TODO call NetworkManager implimation function
    }
}

void GnomeNetworkManagerEvents::onWIFIStateChanged(int state)
{
    NMLOG_INFO("wifi state changed - %d", state);
}

void GnomeNetworkManagerEvents::onAddressChangeCb(std::string iface, std::string ipAddress, bool acqired, bool isIPv6)
{
    static std::map<std::string, std::string> ipv6Map;
    static std::map<std::string, std::string> ipv4Map;

    if (isIPv6)
    {
        if (ipAddress.empty()) {
            ipAddress = ipv6Map[iface];
            ipv6Map[iface].clear();
        }
        else {
            if (ipv6Map[iface].find(ipAddress) == std::string::npos) { // same ip comes multiple time so avoding that
                if (!ipv6Map[iface].empty())
                    ipv6Map[iface] += " ";
                ipv6Map[iface] += ipAddress; // SLAAC protocol may include multip ipv6 address
            }
            else
                return; // skip same ip event posting
        }
    }
    else
    {   // so far same ip only came TODO investigate ?
        if (ipAddress.empty())
            ipAddress = ipv4Map[iface];
        else
            ipv4Map[iface] = ipAddress;
    }
    NMLOG_INFO("iface:%s - ipaddress:%s - %s - isIPv6:%s", iface.c_str(), ipAddress.c_str(), acqired?"acquired":"lost", isIPv6?"true":"false");
    GnomeNetworkManagerEvents::onIPAddressStatusChangedCb(iface, ipv6Map[iface], ipv4Map[iface], acqired);
}

void GnomeNetworkManagerEvents::onAvailableSSIDsCb(NMDeviceWifi *wifiDevice, GParamSpec *pspec, gpointer userData)
{
    NMLOG_INFO("wifi scanning completed ...");
    // TODO crate json object and send it
}

/* legacy events */
void GnomeNetworkManagerEvents::onInterfaceStatusChangedCb(std::string iface, bool enabled)
{
   NMLOG_INFO("interface %s %s", iface.c_str(),enabled?"enabled":"disabled");
}

void GnomeNetworkManagerEvents::onConnectionStatusChangedCb(std::string iface, bool connected)
{
   NMLOG_INFO("interface %s %s", iface.c_str(),connected?"CONNECTED":"DISCONNECTED");
}

void GnomeNetworkManagerEvents::onIPAddressStatusChangedCb(std::string iface, std::string ipv4, std::string ipv6, bool acqired)
{
    NMLOG_INFO("%s: IPv4:%s - IPv6:%s %s", iface.c_str(), ipv4.c_str(), ipv6.c_str(),acqired?"acqired":"lost");
}

/* code need to add in the main code as modification */
static void printActiveAccessPoints(NMDeviceWifi *wifiDevice)
{
    if(!NM_IS_DEVICE_WIFI(wifiDevice))
    {
        NMLOG_ERROR("Not a wifi object ");
        return;
    }
    const GPtrArray *accessPointsArray = nm_device_wifi_get_access_points(wifiDevice);
    for (guint i = 0; i < accessPointsArray->len; i++)
    {
        NMAccessPoint *ap = NULL;
        GBytes *ssidGByte = NULL;
        std::string ssid;

        ap = (NMAccessPoint*)accessPointsArray->pdata[i];
        ssidGByte = nm_access_point_get_ssid(ap);
        if(ssidGByte)
        {
            char* ssidStr = NULL;
            gsize len;
            const guint8 *ssidData = static_cast<const guint8 *>(g_bytes_get_data(ssidGByte, &len));
            ssidStr = nm_utils_ssid_to_utf8(ssidData, len);
            if(ssidStr != NULL) {
                std::string ssidTmp(ssidStr, len);
                ssid = ssidTmp;
            }
            else
                ssid = "---";
        }
        else
            ssid = "---";
    
        NMLOG_INFO("ssid: %s", ssid.c_str());
    }
}

static void wifiScanCb(GObject *object, GAsyncResult *result, gpointer user_data)
{
    GError *error = NULL;
    if(nm_device_wifi_request_scan_finish(NM_DEVICE_WIFI(object), result, &error)) {
        printActiveAccessPoints(NM_DEVICE_WIFI(object));
    }
    else
    {
        NMLOG_ERROR("Scanning Failed");
    }
    if (error) {
         NMLOG_ERROR("Scanning Failed Error: %s.", error->message);
        g_error_free(error);
    }
}

void GnomeNetworkManagerEvents::startWifiScanning(std::string ssidReq)
{
   NMLOG_INFO("staring wifi scanning .. %s", ssidReq.c_str());
   NMDevice *wifiDevice = nm_client_get_device_by_iface(nmEvents.client, "wlan0");

    if(!ssidReq.empty())
    {
        GVariantBuilder builder, array_builder;
        GVariant *options;
        g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
        g_variant_builder_init(&array_builder, G_VARIANT_TYPE("aay"));
        g_variant_builder_add(&array_builder, "@ay",
                            g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, (const guint8 *) ssidReq.c_str(), ssidReq.length(), 1)
                            );
        g_variant_builder_add(&builder, "{sv}", "ssids", g_variant_builder_end(&array_builder));
        options = g_variant_builder_end(&builder);
        nm_device_wifi_request_scan_options_async(NM_DEVICE_WIFI(wifiDevice), options, NULL, wifiScanCb, NULL);
    }
    else {
        NMLOG_INFO("staring normal wifi scanning");
        nm_device_wifi_request_scan_async(NM_DEVICE_WIFI(wifiDevice), NULL, wifiScanCb, NULL);
    }
}
