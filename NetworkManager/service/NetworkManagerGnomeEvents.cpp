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
#include <NetworkManager.h>
#include <libnm/NetworkManager.h>
#include "NetworkManagerGnomeEvents.h"
#include "NetworkManagerLogger.h"

static GnomeNetworkManagerEvents *_nmEventInstance = nullptr;

static void primaryConnectionCb(NMClient *client, GParamSpec *param, gpointer user_data)
{
    NMActiveConnection *primaryConn;
    const char *activeConnId = NULL;
    const char *connectionTyp = NULL;

    primaryConn = nm_client_get_primary_connection(client);
    if (primaryConn)
    {
        activeConnId = nm_active_connection_get_id(primaryConn);
        connectionTyp = nm_active_connection_get_connection_type(primaryConn);
        NMLOG_INFO("active connection - %s (%s)", activeConnId, connectionTyp);

        _nmEventInstance->oldActiveIfaceName = _nmEventInstance->newActiveIfaceName;

        if (0 == strncmp("802-3-ethernet", connectionTyp, sizeof("802-3-ethernet")))
            _nmEventInstance->newActiveIfaceName = "eth0";
        else if(0 == strncmp("802-11-wireless", connectionTyp, sizeof("802-11-wireless")))
            _nmEventInstance->newActiveIfaceName = "wlan0";
        else
            NMLOG_WARNING("active connection not an ethernet/wifi %s", connectionTyp);

        NMLOG_INFO("oldInterfaceName - %s newInterfaceName - %s", _nmEventInstance->oldActiveIfaceName.c_str(), _nmEventInstance->newActiveIfaceName.c_str());
        // TODO brodcast Interface change Event onActiveInterfaceChange
    }
    else
        NMLOG_ERROR("now there's no active connection");
}

GnomeNetworkManagerEvents::GnomeNetworkManagerEvents():client(nullptr), loop(nullptr)
{
    loop = g_main_loop_new(NULL, FALSE);
    if(loop == NULL)
    {
        NMLOG_FATAL("GMain loop failed! Fatal Error: Event will not work");
    }

    if(!createClientNewConnection())
    {
        NMLOG_ERROR("Client Connection failed");
    }

    _nmEventInstance = this;

    NMLOG_INFO("Client Connection success");
}
/*
 *    NM_DEVICE_STATE_UNKNOWN      = 0,
    NM_DEVICE_STATE_UNMANAGED    = 10,
    NM_DEVICE_STATE_UNAVAILABLE  = 20, INTERFACE_LINK_DOWN
    NM_DEVICE_STATE_DISCONNECTED = 30, INTERFACE_LINK_DOWN
    NM_DEVICE_STATE_PREPARE      = 40, INTERFACE_LINK_UP
    NM_DEVICE_STATE_CONFIG       = 50,
    NM_DEVICE_STATE_NEED_AUTH    = 60,
    NM_DEVICE_STATE_IP_CONFIG    = 70, INTERFACE_ACQUIRING_IP
    NM_DEVICE_STATE_IP_CHECK     = 80,
    NM_DEVICE_STATE_SECONDARIES  = 90,
    NM_DEVICE_STATE_ACTIVATED    = 100, wifiConnected
    NM_DEVICE_STATE_DEACTIVATING = 110, 
    NM_DEVICE_STATE_FAILED       = 120, INTERFACE_LINK_DOWN
 *
 */

/*
 switch (state) {
        case NM_DEVICE_STATE_UNKNOWN:
            return 0; // WIFI_STATE_UNINSTALLED
        case NM_DEVICE_STATE_UNMANAGED:
            return 1; // WIFI_STATE_DISABLED
        case NM_DEVICE_STATE_DISCONNECTED:
            return 2; // WIFI_STATE_DISCONNECTED
        case NM_DEVICE_STATE_PREPARE:
            return 3; // WIFI_STATE_PAIRING
        case NM_DEVICE_STATE_CONFIG:
        case NM_DEVICE_STATE_IP_CONFIG:
            return 4; // WIFI_STATE_CONNECTING
        case NM_DEVICE_STATE_ACTIVATED:
            return 5; // WIFI_STATE_CONNECTED
        case NM_DEVICE_STATE_DEACTIVATING:
            return 8; // WIFI_STATE_CONNECTION_LOST
        case NM_DEVICE_STATE_FAILED:
            // Further inspection needed for specific failure reasons
            // For example, invalid credentials or authentication failed
            return 9; // WIFI_STATE_CONNECTION_FAILED
        case NM_DEVICE_STATE_NEED_AUTH:
            return 11; // WIFI_STATE_INVALID_CREDENTIALS
        default:
            return 13; // WIFI_STATE_ERROR
}
*/
static void deviceStateChangeCb(NMDevice *device, GParamSpec *pspec, gpointer user_data)
{
    NMDeviceState deviceState;
    deviceState = nm_device_get_state(device);
    std::string iface = nm_device_get_iface(device);
    if (deviceState <= NM_DEVICE_STATE_DISCONNECTED || deviceState >= NM_DEVICE_STATE_DEACTIVATING) {
        NMDeviceStateReason reason = nm_device_get_state_reason(device);
        NMLOG_WARNING("state change reason %d", reason);
    }

    std::string wifiState = "";
    std::string ifaceStatus = "";

    if(iface == "wlan0")
    {
         switch (deviceState)
         {
            case NM_DEVICE_STATE_UNKNOWN:
                wifiState = "WIFI_STATE_UNINSTALLED";
                break;
            case NM_DEVICE_STATE_UNMANAGED:
                wifiState = "WIFI_STATE_DISABLED";
                break;
            case NM_DEVICE_STATE_DISCONNECTED:
                wifiState = "WIFI_STATE_DISCONNECTED";
                break;
            case NM_DEVICE_STATE_PREPARE:
                wifiState = "WIFI_STATE_PAIRING";
                break;
            case NM_DEVICE_STATE_CONFIG:
                wifiState = "WIFI_STATE_CONNECTING";
                break;
            case NM_DEVICE_STATE_IP_CONFIG:
                // event INTERFACE_ACQUIRING_IP onInterfaceStateChange on wlan0
                wifiState = "WIFI_STATE_CONNECTING";
                break;
            case NM_DEVICE_STATE_ACTIVATED:
                wifiState = "WIFI_STATE_CONNECTED";
                break;
            case NM_DEVICE_STATE_DEACTIVATING:
                wifiState = "NM_DEVICE_STATE_DEACTIVATING";
                break;
            case NM_DEVICE_STATE_FAILED:
                wifiState = "WIFI_STATE_CONNECTION_FAILED";
                break;
            case NM_DEVICE_STATE_NEED_AUTH:
                wifiState = "WIFI_STATE_INVALID_CREDENTIALS";
                break;
            default:
                wifiState = "WIFI_STATE_ERROR";
        }

        NMLOG_INFO("wifi state: %s", wifiState.c_str());
    }
    else if(iface == "eth0")
    {
        switch (deviceState)
        {
        case NM_DEVICE_STATE_FAILED:
        case NM_DEVICE_STATE_UNAVAILABLE:
        case NM_DEVICE_STATE_DISCONNECTED:
                ifaceStatus = "INTERFACE_LINK_DOWN";
            break;
        case NM_DEVICE_STATE_PREPARE:
                ifaceStatus = "INTERFACE_LINK_UP";
            break;
        case NM_DEVICE_STATE_IP_CONFI:
                ifaceStatus = "INTERFAGCE_ACQUIRING_IP";
            break;
        case NM_DEVICE_STATE_ACTIVATED:
            break;
        case NM_DEVICE_STATE_NEED_AUTH:
            break;
        default:
            NMLOG_WARNING("Unhandiled state change ");
            break;
        }

        NMLOG_INFO("%s state: %s(%d)", iface.c_str(), ifaceStatus.c_str(), deviceState);

    }
    else
        NMLOG_ERROR("unknow interface ");
}

static void onActiveConnectionStateChanged(NMActiveConnection *activeConnection, guint state, guint reason, gpointer user_data)
{
    NMLOG_INFO("Active connection state changed: state=%u, reason=%u", state, reason);
    // TODO client.events.onActiveInterfaceChange
    /*
        NM_ACTIVE_CONNECTION_STATE_UNKNOWN      = 0,
        NM_ACTIVE_CONNECTION_STATE_ACTIVATING   = 1,
        NM_ACTIVE_CONNECTION_STATE_ACTIVATED    = 2,
        NM_ACTIVE_CONNECTION_STATE_DEACTIVATING = 3,
        NM_ACTIVE_CONNECTION_STATE_DEACTIVATED  = 4,
    */
}

static void deviceActiveConnChangeCb(NMDevice *device, GParamSpec *pspec, gpointer user_data)
{
    _nmEventInstance->activeConn = nm_device_get_active_connection(device);
    const char *id = _nmEventInstance->activeConn ? nm_active_connection_get_id(_nmEventInstance->activeConn) : NULL;

    if (!id)
        return;
    if (!_nmEventInstance->activeConn) {
        NMLOG_ERROR("No active connections found");
        return ;
    }

    g_signal_connect(_nmEventInstance->activeConn, "state-changed", G_CALLBACK(onActiveConnectionStateChanged), NULL);
    NMLOG_INFO("%s: using connection '%s'", nm_device_get_iface(device), id);
}

static void ip4ChangedCb(NMIPConfig *ipConfig, GParamSpec *pspec, gpointer userData)
{
     // TODO "method": "client.events.onAddressChange"
    if (!ipConfig) {
        NMLOG_ERROR("IP config is null");
        return;
    }

    NMDevice *device = (NMDevice*)userData;
    std::string iface = nm_device_get_iface(device);

    GPtrArray *addresses = nm_ip_config_get_addresses(ipConfig);
    if (!addresses) {
        NMLOG_ERROR("No addresses found");
        return;
    }
    else
    {
        if(addresses->len == 0)
        {
            NMLOG_INFO("%s ipv4 address lost", iface.c_str());
            return;
        }
    }

    for (guint i = 0; i < addresses->len; ++i)
    {
        NMIPAddress *address = (NMIPAddress *)g_ptr_array_index(addresses, i);
        if (nm_ip_address_get_family(address) == AF_INET) {
            const char *ipAddress = nm_ip_address_get_address(address);
            if(ipAddress != NULL)
                NMLOG_INFO("IPv4 Address: %s", ipAddress);
        }
    }
}

static void ip6ChangedCb(NMIPConfig *ipConfig, GParamSpec *pspec, gpointer userData)
{
    if (!ipConfig) {
        NMLOG_ERROR("IP config is null");
        return;
    }

    NMDevice *device = (NMDevice*)userData;
    std::string iface = nm_device_get_iface(device);

    GPtrArray *addresses = nm_ip_config_get_addresses(ipConfig);
    if (!addresses)
    {
        NMLOG_ERROR("No addresses found");
        return;
    }
    else
    {
        if(addresses->len == 0)
        {
             NMLOG_INFO("%s ipv6 address lost", iface.c_str());
            return;
        }
    }

    for (guint i = 0; i < addresses->len; ++i)
    {
        NMIPAddress *address = (NMIPAddress *)g_ptr_array_index(addresses, i);
        if (nm_ip_address_get_family(address) == AF_INET6)
        {
            const char *ipAddress = nm_ip_address_get_address(address);
            int prefix = nm_ip_address_get_prefix(address);
            if(ipAddress != NULL)
                NMLOG_INFO("ipv6 address: %s Prefix: %d ", ipAddress, prefix);
        }
    }
}
static void deviceAddedCB(NMClient *client, NMDevice *device, gpointer user_data)
{
    // TODO client.events.onInterfaceStateChange

    NMLOG_INFO("%s: device added", nm_device_get_iface(device));
    g_signal_connect(device, "notify::" NM_DEVICE_STATE, G_CALLBACK(deviceStateChangeCb), NULL);
    g_signal_connect(device, "notify::" NM_DEVICE_ACTIVE_CONNECTION, G_CALLBACK(deviceActiveConnChangeCb), NULL);

    NMIPConfig *ipv4Config = nm_device_get_ip4_config(device);
    NMIPConfig *ipv6Config = nm_device_get_ip6_config(device);
    if (ipv4Config) {
        g_signal_connect(ipv4Config, "notify::addresses", G_CALLBACK(ip4ChangedCb), device);
    }

    if (ipv6Config) {
        g_signal_connect(ipv6Config, "notify::addresses", G_CALLBACK(ip6ChangedCb), device);
    }
    // TODO remove the signal handler
} 

static void deviceRemovedCB(NMClient *client, NMDevice *device, gpointer userData)
{
    NMLOG_WARNING("%s: device removed", nm_device_get_iface(device));

    if(!device)
    {
        g_signal_handlers_disconnect_by_func(device, (gpointer)deviceStateChangeCb, NULL);
        g_signal_handlers_disconnect_by_func(device, (gpointer)deviceActiveConnChangeCb, NULL);
    }

    if(!_nmEventInstance->activeConn)
    {
        guint disconnected_count = g_signal_handlers_disconnect_matched( _nmEventInstance->activeConn,
                                                                        G_SIGNAL_MATCH_FUNC,
                                                                        0, 0, NULL,
                                                                        (gpointer)onActiveConnectionStateChanged,
                                                                        NULL );
        NMLOG_ERROR("Disconnected %u signal handlers\n", disconnected_count);
    }
        //g_signal_handlers_disconnect_by_func(_nmEventInstance->activeConn,  (gpointer)(onActiveConnectionStateChanged), NULL);
            // Disconnect the signal handler before exiting

    //_nmEventInstance->activeConn = NULL;
}

bool GnomeNetworkManagerEvents::startNetworkMangerDbusEventMonitor()
{
    if (NULL == client)
    {
        NMLOG_ERROR("Client Connection NULL DBUS event Failed!");
        g_main_loop_unref(loop);
        return false;
    }

    primaryConnectionCb(client, NULL, NULL);
    g_signal_connect(client, "notify::" NM_CLIENT_PRIMARY_CONNECTION, G_CALLBACK(primaryConnectionCb), NULL);

    const GPtrArray *devices = nullptr;
    devices = nm_client_get_devices(client);

    g_signal_connect(client, NM_CLIENT_DEVICE_ADDED, G_CALLBACK(deviceAddedCB), NULL);
    g_signal_connect(client, NM_CLIENT_DEVICE_REMOVED, G_CALLBACK(deviceRemovedCB), NULL);

    for (int count = 0; count < devices->len; count++)
    {
        NMDevice *device = NM_DEVICE(g_ptr_array_index(devices, count));

        NMIPConfig *ipv4Config = nm_device_get_ip4_config(device);
        NMIPConfig *ipv6Config = nm_device_get_ip6_config(device);
        g_signal_connect(device, "notify::" NM_DEVICE_STATE, G_CALLBACK(deviceStateChangeCb), NULL);
        g_signal_connect(device, "notify::" NM_DEVICE_ACTIVE_CONNECTION, G_CALLBACK(deviceActiveConnChangeCb), NULL);
        if (ipv4Config) {
            g_signal_connect(ipv4Config, "notify::addresses", G_CALLBACK(ip4ChangedCb), device);
        }

        if (ipv6Config) {
            g_signal_connect(ipv6Config, "notify::addresses", G_CALLBACK(ip6ChangedCb), device);
        }
    }

    g_main_loop_run(loop);
    g_main_loop_unref(loop);

    NMLOG_INFO("Register all dbus events");
    return true;
}

static void wifiScanCb(GObject *object, GAsyncResult *result, gpointer user_data)
{
    GError *error = NULL;
    gboolean success = false;
    if(nm_device_wifi_request_scan_finish(NM_DEVICE_WIFI(object), result, &error)) {
        _nmEventInstance->printAvailbleAccessPoints(NM_DEVICE_WIFI(object));
    }
    if (error) {
         NMLOG_INFO("Error: %s.", error->message);
        g_error_free(error);
    }
}

void GnomeNetworkManagerEvents::printAvailbleAccessPoints(NMDeviceWifi *wifiDevice)
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

void GnomeNetworkManagerEvents::startWifiScanning(std::string ssidReq)
{
   NMLOG_INFO("staring wifi scanning for ...", ssidReq.c_str());
   NMDevice *wifiDevice = nm_client_get_device_by_iface(client, "wlan0");

    if(!ssidReq.empty())
    {
        GVariantBuilder builder, array_builder;
        GVariant *options;
        GError *scan_err = NULL;
        g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
        g_variant_builder_init(&array_builder, G_VARIANT_TYPE("aay"));
        g_variant_builder_add(&array_builder, "@ay",
                            g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, (const guint8 *) ssidReq.c_str(), ssidReq.length(), 1)
                            );
        g_variant_builder_add(&builder, "{sv}", "ssids", g_variant_builder_end(&array_builder));
        options = g_variant_builder_end(&builder);
        nm_device_wifi_request_scan_options_async(NM_DEVICE_WIFI(wifiDevice), NULL, NULL, wifiScanCb, NULL);
    }
    else
        nm_device_wifi_request_scan_async(NM_DEVICE_WIFI(wifiDevice), NULL, wifiScanCb, NULL);

}

void GnomeNetworkManagerEvents::stopNetworkMangerDbusEventMonitor()
{
   // g_signal_handlers_disconnect_by_func(client, G_CALLBACK(primaryConnectionCb), NULL);
   NMLOG_INFO("un registering event handelers");
}

GnomeNetworkManagerEvents::~GnomeNetworkManagerEvents()
{
    NMLOG_TRACE("~GnomeNetworkManagerEvents");
    stopNetworkMangerDbusEventMonitor();
    if(client != nullptr)
        g_object_unref(client);
    if (loop != NULL) {
        g_main_loop_unref(loop);
        loop = NULL;
    }
}

bool GnomeNetworkManagerEvents::createClientNewConnection()
{
    GError *error = NULL;

    if (client != NULL)
    {
        g_object_unref(client);
        client = NULL;
    }

    client = nm_client_new(NULL, &error);
    if(client)
        return true;

    if (error)
    {
        NMLOG_ERROR("Could not connect to NetworkManager: %s", error->message);
        g_error_free(error);
    }
    else
    {
        NMLOG_ERROR("Could not connect to NetworkManager: unknown error");
    }

    return false;
}
