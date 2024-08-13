#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "L2Tests.h"
#include "L2TestsMock.h"
#include <mutex>
#include <condition_variable>
#include <fstream>
#include <interfaces/IStore2.h>
#include <interfaces/IUserSettings.h>

#define TEST_LOG(x, ...) fprintf(stderr, "\033[1;32m[%s:%d](%s)<PID:%d><TID:%d>" x "\n\033[0m", __FILE__, __LINE__, __FUNCTION__, getpid(), gettid(), ##__VA_ARGS__); fflush(stderr);

#define JSON_TIMEOUT   (1000)
#define USERSETTING_CALLSIGN  _T("org.rdk.UserSettings")
#define USERSETTINGL2TEST_CALLSIGN _T("L2tests.1")

using ::testing::NiceMock;
using namespace WPEFramework;
using testing::StrictMock;
using ::WPEFramework::Exchange::IStore2;
using ::WPEFramework::Exchange::IUserSettings;

typedef enum : uint32_t {
    UserSettings_OnAudioDescriptionChanged = 0x00000001,
    UserSettings_OnPreferredAudioLanguagesChanged = 0x00000002,
    UserSettings_OnPresentationLanguageChanged = 0x00000003,
    UserSettings_OnCaptionsChanged = 0x00000004,
    UserSettings_OnPreferredCaptionsLanguagesChanged = 0x00000005,
    UserSettings_OnPreferredClosedCaptionServiceChanged = 0x00000006,
    UserSettings_OnPrivacyModeChanged = 0x00000007,
    UserSettings_StateInvalid = 0x00000000
}UserSettingsL2test_async_events_t;

class AsyncHandlerMock_UserSetting
{
    public:
        AsyncHandlerMock_UserSetting()
        {
        }
        MOCK_METHOD(void, OnAudioDescriptionChanged, (const bool enabled));
        MOCK_METHOD(void, OnPreferredAudioLanguagesChanged, (const string preferredLanguages));
        MOCK_METHOD(void, OnPresentationLanguageChanged, (const string presentationLanguages));
        MOCK_METHOD(void, OnCaptionsChanged, (bool enabled));
        MOCK_METHOD(void, OnPreferredCaptionsLanguagesChanged, (const string preferredLanguages));
        MOCK_METHOD(void, OnPreferredClosedCaptionServiceChanged, (const string service));

};

class NotificationHandler : public Exchange::IUserSettings::INotification {
    private:
        /** @brief Mutex */
        std::mutex m_mutex;

        /** @brief Condition variable */
        std::condition_variable m_condition_variable;

        /** @brief Event signalled flag */
        uint32_t m_event_signalled;

        BEGIN_INTERFACE_MAP(Notification)
        INTERFACE_ENTRY(Exchange::IUserSettings::INotification)
        END_INTERFACE_MAP

    public:
        NotificationHandler(){}
        ~NotificationHandler(){}

        void OnAudioDescriptionChanged(const bool enabled) override
        {
            TEST_LOG("OnAudioDescriptionChanged event triggered ***\n");
            std::unique_lock<std::mutex> lock(m_mutex);
            std::string str = enabled ? "true" : "false";

            TEST_LOG("OnAudioDescriptionChanged received: %s\n", str.c_str());
            /* Notify the requester thread. */
            m_event_signalled |= UserSettings_OnAudioDescriptionChanged;
            m_condition_variable.notify_one();
        }

        void OnPreferredAudioLanguagesChanged(const string& preferredLanguages) override
        {
            TEST_LOG("OnPreferredAudioLanguagesChanged event triggered ***\n");
            std::unique_lock<std::mutex> lock(m_mutex);

            TEST_LOG("OnPreferredAudioLanguagesChanged received: %s\n", preferredLanguages.c_str());
            /* Notify the requester thread. */
            m_event_signalled |= UserSettings_OnPreferredAudioLanguagesChanged;
            m_condition_variable.notify_one();

        }

        void OnPresentationLanguageChanged(const string& presentationLanguages) override
        {
            TEST_LOG("OnPresentationLanguageChanged event triggered ***\n");
            std::unique_lock<std::mutex> lock(m_mutex);

            TEST_LOG("OnPresentationLanguageChanged received: %s\n", presentationLanguages.c_str());
            /* Notify the requester thread. */
            m_event_signalled |= UserSettings_OnPresentationLanguageChanged;
            m_condition_variable.notify_one();

        }

        void OnCaptionsChanged(bool enabled) override
        {
            TEST_LOG("OnCaptionsChanged event triggered ***\n");
            std::unique_lock<std::mutex> lock(m_mutex);
            std::string str = enabled ? "true" : "false";

            TEST_LOG("OnCaptionsChanged received: %s\n", str.c_str());
            /* Notify the requester thread. */
            m_event_signalled |= UserSettings_OnCaptionsChanged;
            m_condition_variable.notify_one();

        }

        void OnPreferredCaptionsLanguagesChanged(const string& preferredLanguages) override
        {
            TEST_LOG("OnPreferredCaptionsLanguagesChanged event triggered ***\n");
            std::unique_lock<std::mutex> lock(m_mutex);

            TEST_LOG("OnPreferredAudioLanguagesChanged received: %s\n", preferredLanguages.c_str());
            /* Notify the requester thread. */
            m_event_signalled |= UserSettings_OnPreferredCaptionsLanguagesChanged;
            m_condition_variable.notify_one();

        }

        void OnPreferredClosedCaptionServiceChanged(const string& service) override
        {
            TEST_LOG("OnPreferredClosedCaptionServiceChanged event triggered ***\n");
            std::unique_lock<std::mutex> lock(m_mutex);

            TEST_LOG("OnPreferredClosedCaptionServiceChanged received: %s\n", service.c_str());
            /* Notify the requester thread. */
            m_event_signalled |= UserSettings_OnPreferredClosedCaptionServiceChanged;
            m_condition_variable.notify_one();

        }

        void OnPrivacyModeChanged(const string& service) override
        {
            TEST_LOG("OnPrivacyModeChanged event triggered ***\n");
            std::unique_lock<std::mutex> lock(m_mutex);

            TEST_LOG("OnPrivacyModeChanged received: %s\n", service.c_str());
            /* Notify the requester thread. */
            m_event_signalled |= UserSettings_OnPrivacyModeChanged;
            m_condition_variable.notify_one();
        }

        uint32_t WaitForRequestStatus(uint32_t timeout_ms, UserSettingsL2test_async_events_t expected_status)
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            auto now = std::chrono::system_clock::now();
            std::chrono::milliseconds timeout(timeout_ms);
            uint32_t signalled = UserSettings_StateInvalid;

            while (!(expected_status & m_event_signalled))
            {
              if (m_condition_variable.wait_until(lock, now + timeout) == std::cv_status::timeout)
              {
                 TEST_LOG("Timeout waiting for request status event");
                 break;
              }
            }

            signalled = m_event_signalled;
            return signalled;
        }
    };

class UserSettingTest : public L2TestMocks {
protected:
    virtual ~UserSettingTest() override;

    public:
    UserSettingTest();

      void OnAudioDescriptionChanged(const bool enabled);
      void OnPreferredAudioLanguagesChanged(const string preferredLanguages);
      void OnPresentationLanguageChanged(const string presentationLanguages);
      void OnCaptionsChanged(bool enabled);
      void OnPreferredCaptionsLanguagesChanged(const string preferredLanguages);
      void OnPreferredClosedCaptionServiceChanged(const string service);

      uint32_t WaitForRequestStatus(uint32_t timeout_ms,UserSettingsL2test_async_events_t expected_status);
      uint32_t CreateUserSettingInterfaceObjectUsingComRPCConnection();

    private:
        /** @brief Mutex */
        std::mutex m_mutex;

        /** @brief Condition variable */
        std::condition_variable m_condition_variable;

        /** @brief Event signalled flag */
        uint32_t m_event_signalled;

    protected:
        /** @brief Pointer to the IShell interface */
        PluginHost::IShell *m_controller_usersettings;

        /** @brief Pointer to the IUserSettings interface */
        Exchange::IUserSettings *m_usersettingsplugin;
};

UserSettingTest:: UserSettingTest():L2TestMocks()
{
        Core::JSONRPC::Message message;
        string response;
        uint32_t status = Core::ERROR_GENERAL;

         /* Activate plugin in constructor */
         status = ActivateService("org.rdk.PersistentStore");
         EXPECT_EQ(Core::ERROR_NONE, status);
         status = ActivateService("org.rdk.UserSettings");
         EXPECT_EQ(Core::ERROR_NONE, status);
}

/**
 * @brief Destructor for SystemServices L2 test class
 */
UserSettingTest::~UserSettingTest()
{
    uint32_t status = Core::ERROR_GENERAL;

    ON_CALL(*p_rBusApiImplMock, rbus_close(::testing::_ ))
        .WillByDefault(
           ::testing::Return(RBUS_ERROR_SUCCESS));

    status = DeactivateService("org.rdk.UserSettings");
    EXPECT_EQ(Core::ERROR_NONE, status);

    status = DeactivateService("org.rdk.PersistentStore");
    EXPECT_EQ(Core::ERROR_NONE, status);

    int file_status = remove("/tmp/secure/persistent/rdkservicestore");
    // Check if the file has been successfully removed
    if (file_status != 0)
    {
        TEST_LOG("Error deleting file[/tmp/secure/persistent/rdkservicestore]");
    }
    else
    {
        TEST_LOG("File[/tmp/secure/persistent/rdkservicestore] successfully deleted");
    }
}

uint32_t UserSettingTest::WaitForRequestStatus(uint32_t timeout_ms, UserSettingsL2test_async_events_t expected_status)
{
    std::unique_lock<std::mutex> lock(m_mutex);
    auto now = std::chrono::system_clock::now();
    std::chrono::milliseconds timeout(timeout_ms);
    uint32_t signalled = UserSettings_StateInvalid;

   while (!(expected_status & m_event_signalled))
   {
      if (m_condition_variable.wait_until(lock, now + timeout) == std::cv_status::timeout)
      {
         TEST_LOG("Timeout waiting for request status event");
         break;
      }
   }

    signalled = m_event_signalled;
    return signalled;
}
uint32_t UserSettingTest::CreateUserSettingInterfaceObjectUsingComRPCConnection()
{
    uint32_t return_value =  Core::ERROR_GENERAL;
    Core::ProxyType<RPC::InvokeServerType<1, 0, 4>> Engine_UserSettings;
    Core::ProxyType<RPC::CommunicatorClient> Client_UserSettings;

    TEST_LOG("Creating Engine_UserSettings");
    Engine_UserSettings = Core::ProxyType<RPC::InvokeServerType<1, 0, 4>>::Create();
    Client_UserSettings = Core::ProxyType<RPC::CommunicatorClient>::Create(Core::NodeId("/tmp/communicator"), Core::ProxyType<Core::IIPCServer>(Engine_UserSettings));

    TEST_LOG("Creating Engine_UserSettings Announcements");
#if ((THUNDER_VERSION == 2) || ((THUNDER_VERSION == 4) && (THUNDER_VERSION_MINOR == 2)))
    Engine_UserSettings->Announcements(mClient_UserSettings->Announcement());
#endif
    if (!Client_UserSettings.IsValid())
    {
        TEST_LOG("Invalid Client_UserSettings");
    }
    else
    {
        m_controller_usersettings = Client_UserSettings->Open<PluginHost::IShell>(_T("org.rdk.UserSettings"), ~0, 3000);
        if (m_controller_usersettings)
        {
        m_usersettingsplugin = m_controller_usersettings->QueryInterface<Exchange::IUserSettings>();
        return_value = Core::ERROR_NONE;
        }
    }
    return return_value;
}

void UserSettingTest::OnAudioDescriptionChanged(const bool enabled)
{
    TEST_LOG("OnAudioDescriptionChanged event triggered ***\n");
    std::unique_lock<std::mutex> lock(m_mutex);

    std::string str = enabled ? "true" : "false";
    TEST_LOG("OnAudioDescriptionChanged received: %s\n", str.c_str());

    /* Notify the requester thread. */
    m_event_signalled |= UserSettings_OnAudioDescriptionChanged;
    m_condition_variable.notify_one();
}

void UserSettingTest::OnPreferredAudioLanguagesChanged(const string preferredLanguages)
{
    TEST_LOG("OnPreferredAudioLanguagesChanged event triggered ***\n");
    std::unique_lock<std::mutex> lock(m_mutex);

    TEST_LOG("OnPreferredAudioLanguagesChanged received: %s\n", preferredLanguages.c_str());

    /* Notify the requester thread. */
    m_event_signalled |= UserSettings_OnPreferredAudioLanguagesChanged;
    m_condition_variable.notify_one();
}

void UserSettingTest::OnPresentationLanguageChanged(const string presentationLanguages)
{
    TEST_LOG("OnPresentationLanguageChanged event triggered ***\n");
    std::unique_lock<std::mutex> lock(m_mutex);

    TEST_LOG("OnPresentationLanguageChanged received: %s\n", presentationLanguages.c_str());

    /* Notify the requester thread. */
    m_event_signalled |= UserSettings_OnPresentationLanguageChanged;
    m_condition_variable.notify_one();
}

void UserSettingTest::OnCaptionsChanged(bool enabled)
{
    TEST_LOG("OnCaptionsChanged event triggered ***\n");
    std::unique_lock<std::mutex> lock(m_mutex);

    std::string str = enabled ? "true" : "false";
    TEST_LOG("OnCaptionsChanged received: %s\n", str.c_str());

    /* Notify the requester thread. */
    m_event_signalled |= UserSettings_OnCaptionsChanged;
    m_condition_variable.notify_one();
}

void UserSettingTest::OnPreferredCaptionsLanguagesChanged(const string preferredLanguages)
{
    TEST_LOG("OnPreferredCaptionsLanguagesChanged event triggered ***\n");
    std::unique_lock<std::mutex> lock(m_mutex);

    TEST_LOG("OnPreferredAudioLanguagesChanged received: %s\n", preferredLanguages.c_str());

    /* Notify the requester thread. */
    m_event_signalled |= UserSettings_OnPreferredCaptionsLanguagesChanged;
    m_condition_variable.notify_one();
}

void UserSettingTest::OnPreferredClosedCaptionServiceChanged(const string service)
{
    TEST_LOG("OnPreferredClosedCaptionServiceChanged event triggered ***\n");
    std::unique_lock<std::mutex> lock(m_mutex);

    TEST_LOG("OnPreferredClosedCaptionServiceChanged received: %s\n", service.c_str());

    /* Notify the requester thread. */
    m_event_signalled |= UserSettings_OnPreferredClosedCaptionServiceChanged;
    m_condition_variable.notify_one();
}

MATCHER_P(MatchRequestStatusString, data, "")
{
    std::string actual = arg;
    TEST_LOG("Expected: %s, Actual: %s", data.c_str(), actual.c_str());
    EXPECT_STREQ(data.c_str(), actual.c_str());
    return data == actual;

}

MATCHER_P(MatchRequestStatusBool, expected, "")
{
    bool actual = arg;
    std::string expected_str = expected ? "true" : "false";
    std::string actual_str = actual ? "true" : "false";
    TEST_LOG("Expected: %s, Actual: %s", expected_str.c_str(), actual_str.c_str());
    EXPECT_STREQ(expected_str.c_str(), actual_str.c_str());
    return expected == actual;
}

/* Activating UserSettings and Persistent store plugins and UserSettings namespace has no entries in db.
   So that we can verify whether UserSettings plugin is receiving default values from PersistentStore or not*/
TEST_F(UserSettingTest, VerifyDefaultValues)
{
    uint32_t status = Core::ERROR_GENERAL;
    uint32_t signalled = UserSettings_StateInvalid;
    Core::Sink<NotificationHandler> notification;
    bool defaultBooleanValue = true;
    string defaultStrValue = "eng";

    if (CreateUserSettingInterfaceObjectUsingComRPCConnection() != Core::ERROR_NONE)
    {
        TEST_LOG("Invalid Client_UserSettings");
    }
    else
    {
        ASSERT_TRUE(m_controller_usersettings!= nullptr);
        if (m_controller_usersettings)
        {
            ASSERT_TRUE(m_usersettingsplugin!= nullptr);
            if (m_usersettingsplugin)
            {
                m_usersettingsplugin->AddRef();
                m_usersettingsplugin->Register(&notification);

                /* defaultBooleanValue should get false and the return status is Core::ERROR_NONE */
                status = m_usersettingsplugin->GetAudioDescription(defaultBooleanValue);
                EXPECT_EQ(defaultBooleanValue, false);
                EXPECT_EQ(status,Core::ERROR_NONE);
                if (status != Core::ERROR_NONE)
                {
                    std::string errorMsg = "COM-RPC returned error " + std::to_string(status) + " (" + std::string(Core::ErrorToString(status)) + ")";
                    TEST_LOG("Err: %s", errorMsg.c_str());
                }

                /* defaultStrValue should get empty string and the return status is Core::ERROR_NONE */
                status = m_usersettingsplugin->GetPreferredAudioLanguages(defaultStrValue);
                EXPECT_EQ(defaultStrValue, "");
                EXPECT_EQ(status,Core::ERROR_NONE);
                if (status != Core::ERROR_NONE)
                {
                    std::string errorMsg = "COM-RPC returned error " + std::to_string(status) + " (" + std::string(Core::ErrorToString(status)) + ")";
                    TEST_LOG("Err: %s", errorMsg.c_str());
                }

                /* defaultStrValue should get empty string and the return status is Core::ERROR_NONE */
                status = m_usersettingsplugin->GetPresentationLanguage(defaultStrValue);
                EXPECT_EQ(defaultStrValue, "");
                EXPECT_EQ(status,Core::ERROR_NONE);
                if (status != Core::ERROR_NONE)
                {
                    std::string errorMsg = "COM-RPC returned error " + std::to_string(status) + " (" + std::string(Core::ErrorToString(status)) + ")";
                    TEST_LOG("Err: %s", errorMsg.c_str());
                }

                /* defaultBooleanValue should get false and the return status is Core::ERROR_NONE */
                status = m_usersettingsplugin->GetCaptions(defaultBooleanValue);
                EXPECT_EQ(defaultBooleanValue, false);
                EXPECT_EQ(status,Core::ERROR_NONE);
                if (status != Core::ERROR_NONE)
                {
                    std::string errorMsg = "COM-RPC returned error " + std::to_string(status) + " (" + std::string(Core::ErrorToString(status)) + ")";
                    TEST_LOG("Err: %s", errorMsg.c_str());
                }

                /* defaultStrValue should get empty string and the return status is Core::ERROR_NONE */
                status = m_usersettingsplugin->GetPreferredCaptionsLanguages(defaultStrValue);
                EXPECT_EQ(defaultStrValue, "");
                EXPECT_EQ(status,Core::ERROR_NONE);
                if (status != Core::ERROR_NONE)
                {
                    std::string errorMsg = "COM-RPC returned error " + std::to_string(status) + " (" + std::string(Core::ErrorToString(status)) + ")";
                    TEST_LOG("Err: %s", errorMsg.c_str());
                }

                /* defaultStrValue should get "AUTO" and the return status is Core::ERROR_NONE */
                status = m_usersettingsplugin->GetPreferredClosedCaptionService(defaultStrValue);
                EXPECT_EQ(defaultStrValue, "AUTO");
                EXPECT_EQ(status,Core::ERROR_NONE);
                if (status != Core::ERROR_NONE)
                {
                    std::string errorMsg = "COM-RPC returned error " + std::to_string(status) + " (" + std::string(Core::ErrorToString(status)) + ")";
                    TEST_LOG("Err: %s", errorMsg.c_str());
                }

                 /* Setting Audio Description value as true.So UserSettings namespace has one entry in db.
                 But we are trying to get PreferredAudioLanguages, which has no entry in db.
                 So GetPreferredAudioLanguages should return the empty string and the return status
                 from Persistant store is  Core::ERROR_UNKNOWN_KEY and return status from usersettings is Core::ERROR_NONE */
                 status = m_usersettingsplugin->SetAudioDescription(defaultBooleanValue);
                 EXPECT_EQ(status,Core::ERROR_NONE);
                 if (status != Core::ERROR_NONE)
                 {
                     std::string errorMsg = "COM-RPC returned error " + std::to_string(status) + " (" + std::string(Core::ErrorToString(status)) + ")";
                     TEST_LOG("Err: %s", errorMsg.c_str());
                 }

                 signalled = notification.WaitForRequestStatus(JSON_TIMEOUT,UserSettings_OnAudioDescriptionChanged);
                 EXPECT_TRUE(signalled & UserSettings_OnAudioDescriptionChanged);

                 /* We are trying to get PreferredAudioLanguages, which has no entry in db.
                 Persistant store returns status as Core::ERROR_UNKNOWN_KEY to UserSettings 
                 GetPreferredAudioLanguages should get the empty string.*/
                status = m_usersettingsplugin->GetPreferredAudioLanguages(defaultStrValue);
                EXPECT_EQ(defaultStrValue, "");
                EXPECT_EQ(status,Core::ERROR_NONE);
                if (status != Core::ERROR_NONE)
                {
                    std::string errorMsg = "COM-RPC returned error " + std::to_string(status) + " (" + std::string(Core::ErrorToString(status)) + ")";
                    TEST_LOG("Err: %s", errorMsg.c_str());
                }

                /* We are trying to get PresentationLanguage, which has no entry in db.
                Persistant store returns status as Core::ERROR_UNKNOWN_KEY to UserSettings 
                GetPreferredAudioLanguages should get the empty string.*/
                status = m_usersettingsplugin->GetPresentationLanguage(defaultStrValue);
                EXPECT_EQ(defaultStrValue, "");
                EXPECT_EQ(status,Core::ERROR_NONE);
                if (status != Core::ERROR_NONE)
                {
                    std::string errorMsg = "COM-RPC returned error " + std::to_string(status) + " (" + std::string(Core::ErrorToString(status)) + ")";
                    TEST_LOG("Err: %s", errorMsg.c_str());
                }

                /* We are trying to get Captions, which has no entry in db.
                Persistant store returns status as Core::ERROR_UNKNOWN_KEY to UserSettings 
                GetPreferredAudioLanguages should get the empty string.*/
                status = m_usersettingsplugin->GetCaptions(defaultBooleanValue);
                EXPECT_EQ(defaultBooleanValue, false);
                EXPECT_EQ(status,Core::ERROR_NONE);
                if (status != Core::ERROR_NONE)
                {
                    std::string errorMsg = "COM-RPC returned error " + std::to_string(status) + " (" + std::string(Core::ErrorToString(status)) + ")";
                    TEST_LOG("Err: %s", errorMsg.c_str());
                }

                /* We are trying to get PreferredCaptionsLanguages, which has no entry in db.
                Persistant store returns status as Core::ERROR_UNKNOWN_KEY to UserSettings 
                GetPreferredAudioLanguages should get the empty string.*/
                status = m_usersettingsplugin->GetPreferredCaptionsLanguages(defaultStrValue);
                EXPECT_EQ(defaultStrValue, "");
                EXPECT_EQ(status,Core::ERROR_NONE);
                if (status != Core::ERROR_NONE)
                {
                    std::string errorMsg = "COM-RPC returned error " + std::to_string(status) + " (" + std::string(Core::ErrorToString(status)) + ")";
                    TEST_LOG("Err: %s", errorMsg.c_str());
                }

                /* We are trying to get PreferredClosedCaptionService, which has no entry in db.
                Persistant store returns status as Core::ERROR_UNKNOWN_KEY to UserSettings 
                GetPreferredAudioLanguages should get the empty string.*/
                status = m_usersettingsplugin->GetPreferredClosedCaptionService(defaultStrValue);
                EXPECT_EQ(defaultStrValue, "AUTO");
                EXPECT_EQ(status,Core::ERROR_NONE);
                if (status != Core::ERROR_NONE)
                {
                    std::string errorMsg = "COM-RPC returned error " + std::to_string(status) + " (" + std::string(Core::ErrorToString(status)) + ")";
                    TEST_LOG("Err: %s", errorMsg.c_str());
                }

                m_usersettingsplugin->Unregister(&notification);
                m_usersettingsplugin->Release();
            }
            else
            {
                TEST_LOG("m_usersettingsplugin is NULL");
            }
            m_controller_usersettings->Release();
        }
        else
        {
            TEST_LOG("m_controller_usersettings is NULL");
        }
    }
}

TEST_F(UserSettingTest, SetAndGetMethodsUsingJsonRpcConnectionSuccessCase)
{
    JSONRPC::LinkType<Core::JSON::IElement> jsonrpc(USERSETTING_CALLSIGN, USERSETTINGL2TEST_CALLSIGN);
    StrictMock<AsyncHandlerMock_UserSetting> async_handler;
    uint32_t status = Core::ERROR_GENERAL;
    uint32_t signalled = UserSettings_StateInvalid;

    bool enabled = true;
    string preferredLanguages = "en";
    string presentationLanguages = "fra";
    string preferredCaptionsLanguages = "en,es";
    string preferredService = "CC3";
    Core::JSON::String result_string;
    Core::JSON::Boolean result_bool;
    JsonObject result_json;

    TEST_LOG("Testing AudioDescriptionSuccess");
    status = jsonrpc.Subscribe<JsonObject>(JSON_TIMEOUT,
                                       _T("OnAudioDescriptionChanged"),
                                       [this, &async_handler](const JsonObject& parameters) {
                                           bool enabled = parameters["enabled"].Boolean();
                                           async_handler.OnAudioDescriptionChanged(enabled);
                                       });
    EXPECT_EQ(Core::ERROR_NONE, status);

    EXPECT_CALL(async_handler, OnAudioDescriptionChanged(MatchRequestStatusBool(enabled)))
    .WillOnce(Invoke(this, &UserSettingTest::OnAudioDescriptionChanged));

    JsonObject paramsAudioDes;
    paramsAudioDes["enabled"] = true;
    status = InvokeServiceMethod("org.rdk.UserSettings", "SetAudioDescription", paramsAudioDes, result_json);
    EXPECT_EQ(status,Core::ERROR_NONE);

    signalled = WaitForRequestStatus(JSON_TIMEOUT,UserSettings_OnAudioDescriptionChanged);
    EXPECT_TRUE(signalled & UserSettings_OnAudioDescriptionChanged);

    /* Unregister for events. */
    jsonrpc.Unsubscribe(JSON_TIMEOUT, _T("OnAudioDescriptionChanged"));
    EXPECT_EQ(status,Core::ERROR_NONE);

    status = InvokeServiceMethod("org.rdk.UserSettings", "GetAudioDescription", result_bool);
    EXPECT_EQ(status, Core::ERROR_NONE);
    EXPECT_TRUE(result_bool.Value());

    TEST_LOG("Testing PreferredAudioLanguagesSuccess");
    status = jsonrpc.Subscribe<JsonObject>(JSON_TIMEOUT,
                                           _T("OnPreferredAudioLanguagesChanged"),
                                           [&async_handler](const JsonObject& parameters) {
                                           string preferredLanguages = parameters["preferredLanguages"].String();
                                           async_handler.OnPreferredAudioLanguagesChanged(preferredLanguages);
                                       });
    EXPECT_EQ(Core::ERROR_NONE, status);

    EXPECT_CALL(async_handler, OnPreferredAudioLanguagesChanged(MatchRequestStatusString(preferredLanguages)))
    .WillOnce(Invoke(this, &UserSettingTest::OnPreferredAudioLanguagesChanged));

    JsonObject paramsAudioLanguage;
    paramsAudioLanguage["preferredLanguages"] = preferredLanguages;
    status = InvokeServiceMethod("org.rdk.UserSettings", "SetPreferredAudioLanguages", paramsAudioLanguage, result_json);
    EXPECT_EQ(status,Core::ERROR_NONE);

    signalled = WaitForRequestStatus(JSON_TIMEOUT,UserSettings_OnPreferredAudioLanguagesChanged);
    EXPECT_TRUE(signalled & UserSettings_OnPreferredAudioLanguagesChanged);
    jsonrpc.Unsubscribe(JSON_TIMEOUT, _T("OnPreferredAudioLanguagesChanged"));

    status = InvokeServiceMethod("org.rdk.UserSettings", "GetPreferredAudioLanguages", result_string);
    EXPECT_EQ(status,Core::ERROR_NONE);
    EXPECT_EQ(result_string.Value(), preferredLanguages);

    TEST_LOG("Testing PresentationLanguageSuccess");
    status = jsonrpc.Subscribe<JsonObject>(JSON_TIMEOUT,
                                           _T("OnPresentationLanguageChanged"),
                                           [&async_handler](const JsonObject& parameters) {
                                           string presentationLanguages = parameters["presentationLanguages"].String();
                                           async_handler.OnPresentationLanguageChanged(presentationLanguages);
                                       });
    EXPECT_EQ(Core::ERROR_NONE, status);

    EXPECT_CALL(async_handler, OnPresentationLanguageChanged(MatchRequestStatusString(presentationLanguages)))
    .WillOnce(Invoke(this, &UserSettingTest::OnPresentationLanguageChanged));

    JsonObject paramsPresLanguage;
    paramsPresLanguage["presentationLanguages"] = presentationLanguages;
    status = InvokeServiceMethod("org.rdk.UserSettings", "SetPresentationLanguage", paramsPresLanguage, result_json);
    EXPECT_EQ(status,Core::ERROR_NONE);

    signalled = WaitForRequestStatus(JSON_TIMEOUT, UserSettings_OnPresentationLanguageChanged);
    EXPECT_TRUE(signalled & UserSettings_OnPresentationLanguageChanged);
    jsonrpc.Unsubscribe(JSON_TIMEOUT, _T("OnPresentationLanguageChanged"));

    status = InvokeServiceMethod("org.rdk.UserSettings", "GetPresentationLanguage", result_string);
    EXPECT_EQ(status,Core::ERROR_NONE);
    EXPECT_EQ(result_string.Value(), presentationLanguages);

    TEST_LOG("Testing SetCaptionsSuccess");
    status = jsonrpc.Subscribe<JsonObject>(JSON_TIMEOUT,
                                       _T("OnCaptionsChanged"),
                                       [this, &async_handler](const JsonObject& parameters) {
                                           bool enabled = parameters["enabled"].Boolean();
                                           async_handler.OnCaptionsChanged(enabled);
                                       });
    EXPECT_EQ(Core::ERROR_NONE, status);

    EXPECT_CALL(async_handler, OnCaptionsChanged(MatchRequestStatusBool(enabled)))
    .WillOnce(Invoke(this, &UserSettingTest::OnCaptionsChanged));

    JsonObject paramsCaptions;
    paramsCaptions["enabled"] = true;
    status = InvokeServiceMethod("org.rdk.UserSettings", "SetCaptions", paramsCaptions, result_json);
    EXPECT_EQ(status,Core::ERROR_NONE);

    signalled = WaitForRequestStatus(JSON_TIMEOUT,UserSettings_OnCaptionsChanged);
    EXPECT_TRUE(signalled & UserSettings_OnCaptionsChanged);
    jsonrpc.Unsubscribe(JSON_TIMEOUT, _T("OnCaptionsChanged"));

    status = InvokeServiceMethod("org.rdk.UserSettings", "GetCaptions", result_bool);
    EXPECT_EQ(status,Core::ERROR_NONE);
    EXPECT_TRUE(result_bool.Value());

    TEST_LOG("Testing SetPreferredCaptionsLanguagesSuccess");
    status = jsonrpc.Subscribe<JsonObject>(JSON_TIMEOUT,
                                           _T("OnPreferredCaptionsLanguagesChanged"),
                                           [&async_handler](const JsonObject& parameters) {
                                           string preferredCaptionsLanguages = parameters["preferredLanguages"].String();
                                           async_handler.OnPreferredCaptionsLanguagesChanged(preferredCaptionsLanguages);
                                       });
    EXPECT_EQ(Core::ERROR_NONE, status);

    EXPECT_CALL(async_handler, OnPreferredCaptionsLanguagesChanged(MatchRequestStatusString(preferredCaptionsLanguages)))
    .WillOnce(Invoke(this, &UserSettingTest::OnPreferredCaptionsLanguagesChanged));

    JsonObject paramsPrefLang;
    paramsPrefLang["preferredLanguages"] = preferredCaptionsLanguages;
    status = InvokeServiceMethod("org.rdk.UserSettings", "SetPreferredCaptionsLanguages", paramsPrefLang, result_json);
    EXPECT_EQ(status,Core::ERROR_NONE);

    signalled = WaitForRequestStatus(JSON_TIMEOUT,UserSettings_OnPreferredCaptionsLanguagesChanged);
    EXPECT_TRUE(signalled & UserSettings_OnPreferredCaptionsLanguagesChanged);
    jsonrpc.Unsubscribe(JSON_TIMEOUT, _T("OnPreferredCaptionsLanguagesChanged"));

    status = InvokeServiceMethod("org.rdk.UserSettings", "GetPreferredCaptionsLanguages", result_string);
    EXPECT_EQ(status,Core::ERROR_NONE);
    EXPECT_EQ(result_string.Value(), preferredCaptionsLanguages);

    TEST_LOG("Testing SetPreferredClosedCaptionServiceSuccess");
    status = jsonrpc.Subscribe<JsonObject>(JSON_TIMEOUT,
                                           _T("OnPreferredClosedCaptionServiceChanged"),
                                           [&async_handler](const JsonObject& parameters) {
                                           string preferredService = parameters["service"].String();
                                           async_handler.OnPreferredClosedCaptionServiceChanged(preferredService);
                                       });
    EXPECT_EQ(Core::ERROR_NONE, status);

    EXPECT_CALL(async_handler, OnPreferredClosedCaptionServiceChanged(MatchRequestStatusString(preferredService)))
    .WillOnce(Invoke(this, &UserSettingTest::OnPreferredClosedCaptionServiceChanged));

    JsonObject paramspreferredService;
    paramspreferredService["service"] = preferredService;
    status = InvokeServiceMethod("org.rdk.UserSettings", "SetPreferredClosedCaptionService", paramspreferredService, result_json);
    EXPECT_EQ(status,Core::ERROR_NONE);

    signalled = WaitForRequestStatus(JSON_TIMEOUT,UserSettings_OnPreferredClosedCaptionServiceChanged);
    EXPECT_TRUE(signalled & UserSettings_OnPreferredClosedCaptionServiceChanged);
    jsonrpc.Unsubscribe(JSON_TIMEOUT, _T("OnPreferredClosedCaptionServiceChanged"));

    status = InvokeServiceMethod("org.rdk.UserSettings", "GetPreferredClosedCaptionService", result_string);
    EXPECT_EQ(status,Core::ERROR_NONE);
    EXPECT_EQ(result_string.Value(), preferredService);
}

TEST_F(UserSettingTest,SetAndGetMethodsUsingComRpcConnectionSuccessCase)
{
    uint32_t status = Core::ERROR_GENERAL;
    bool getBoolValue = false;
    string getStringValue = "";
    Core::Sink<NotificationHandler> notification;
    uint32_t signalled = UserSettings_StateInvalid;

    if (CreateUserSettingInterfaceObjectUsingComRPCConnection() != Core::ERROR_NONE)
    {
        TEST_LOG("Invalid Client_UserSettings");
    }
    else
    {
        ASSERT_TRUE(m_controller_usersettings!= nullptr);
        if (m_controller_usersettings)
        {
            ASSERT_TRUE(m_usersettingsplugin!= nullptr);
            if (m_usersettingsplugin)
            {
                m_usersettingsplugin->AddRef();
                m_usersettingsplugin->Register(&notification);

                TEST_LOG("Setting and Getting AudioDescription Values");
                status = m_usersettingsplugin->SetAudioDescription(true);
                EXPECT_EQ(status,Core::ERROR_NONE);
                if (status != Core::ERROR_NONE)
                {
                    std::string errorMsg = "COM-RPC returned error " + std::to_string(status) + " (" + std::string(Core::ErrorToString(status)) + ")";
                    TEST_LOG("Err: %s", errorMsg.c_str());
                }
                signalled = notification.WaitForRequestStatus(JSON_TIMEOUT, UserSettings_OnAudioDescriptionChanged);
                EXPECT_TRUE(signalled & UserSettings_OnAudioDescriptionChanged);

                status = m_usersettingsplugin->GetAudioDescription(getBoolValue);
                EXPECT_EQ(getBoolValue, true);
                EXPECT_EQ(status,Core::ERROR_NONE);
                if (status != Core::ERROR_NONE)
                {
                    std::string errorMsg = "COM-RPC returned error " + std::to_string(status) + " (" + std::string(Core::ErrorToString(status)) + ")";
                    TEST_LOG("Err: %s", errorMsg.c_str());
                }

                TEST_LOG("Setting and Getting PreferredAudioLanguages Values");
                status = m_usersettingsplugin->SetPreferredAudioLanguages("eng");
                EXPECT_EQ(status,Core::ERROR_NONE);
                if (status != Core::ERROR_NONE)
                {
                    std::string errorMsg = "COM-RPC returned error " + std::to_string(status) + " (" + std::string(Core::ErrorToString(status)) + ")";
                    TEST_LOG("Err: %s", errorMsg.c_str());
                }
                signalled = notification.WaitForRequestStatus(JSON_TIMEOUT,UserSettings_OnPreferredAudioLanguagesChanged);
                EXPECT_TRUE(signalled & UserSettings_OnPreferredAudioLanguagesChanged);

                status = m_usersettingsplugin->GetPreferredAudioLanguages(getStringValue);
                EXPECT_EQ(getStringValue, "eng");
                EXPECT_EQ(status,Core::ERROR_NONE);
                if (status != Core::ERROR_NONE)
                {
                    std::string errorMsg = "COM-RPC returned error " + std::to_string(status) + " (" + std::string(Core::ErrorToString(status)) + ")";
                    TEST_LOG("Err: %s", errorMsg.c_str());
                }

                TEST_LOG("Setting and Getting PresentationLanguage Values");
                status = m_usersettingsplugin->SetPresentationLanguage("fra");
                EXPECT_EQ(status,Core::ERROR_NONE);
                if (status != Core::ERROR_NONE)
                {
                    std::string errorMsg = "COM-RPC returned error " + std::to_string(status) + " (" + std::string(Core::ErrorToString(status)) + ")";
                    TEST_LOG("Err: %s", errorMsg.c_str());
                }
                signalled = notification.WaitForRequestStatus(JSON_TIMEOUT,UserSettings_OnPresentationLanguageChanged);
                EXPECT_TRUE(signalled & UserSettings_OnPresentationLanguageChanged);

                status = m_usersettingsplugin->GetPresentationLanguage(getStringValue);
                EXPECT_EQ(getStringValue, "fra");
                EXPECT_EQ(status,Core::ERROR_NONE);
                if (status != Core::ERROR_NONE)
                {
                    std::string errorMsg = "COM-RPC returned error " + std::to_string(status) + " (" + std::string(Core::ErrorToString(status)) + ")";
                    TEST_LOG("Err: %s", errorMsg.c_str());
                }

                TEST_LOG("Setting and Getting Captions Values");
                getBoolValue = false;
                status = m_usersettingsplugin->SetCaptions(true);
                EXPECT_EQ(status,Core::ERROR_NONE);
                if (status != Core::ERROR_NONE)
                {
                    std::string errorMsg = "COM-RPC returned error " + std::to_string(status) + " (" + std::string(Core::ErrorToString(status)) + ")";
                    TEST_LOG("Err: %s", errorMsg.c_str());
                }
                signalled = notification.WaitForRequestStatus(JSON_TIMEOUT,UserSettings_OnCaptionsChanged);
                EXPECT_TRUE(signalled & UserSettings_OnCaptionsChanged);

                status = m_usersettingsplugin->GetCaptions(getBoolValue);
                EXPECT_EQ(getBoolValue, true);
                EXPECT_EQ(status,Core::ERROR_NONE);
                if (status != Core::ERROR_NONE)
                {
                    std::string errorMsg = "COM-RPC returned error " + std::to_string(status) + " (" + std::string(Core::ErrorToString(status)) + ")";
                    TEST_LOG("Err: %s", errorMsg.c_str());
                }

                TEST_LOG("Setting and Getting Captions Values");
                status = m_usersettingsplugin->SetPreferredCaptionsLanguages("en,es");
                EXPECT_EQ(status,Core::ERROR_NONE);
                if (status != Core::ERROR_NONE)
                {
                    std::string errorMsg = "COM-RPC returned error " + std::to_string(status) + " (" + std::string(Core::ErrorToString(status)) + ")";
                    TEST_LOG("Err: %s", errorMsg.c_str());
                }
                signalled = notification.WaitForRequestStatus(JSON_TIMEOUT,UserSettings_OnPreferredCaptionsLanguagesChanged);
                EXPECT_TRUE(signalled & UserSettings_OnPreferredCaptionsLanguagesChanged);

                status = m_usersettingsplugin->GetPreferredCaptionsLanguages(getStringValue);
                EXPECT_EQ(getStringValue, "en,es");
                EXPECT_EQ(status,Core::ERROR_NONE);
                if (status != Core::ERROR_NONE)
                {
                    std::string errorMsg = "COM-RPC returned error " + std::to_string(status) + " (" + std::string(Core::ErrorToString(status)) + ")";
                    TEST_LOG("Err: %s", errorMsg.c_str());
                }

                TEST_LOG("Setting and Getting PreferredClosedCaptionService Values");
                status = m_usersettingsplugin->SetPreferredClosedCaptionService("CC3");
                EXPECT_EQ(status,Core::ERROR_NONE);
                if (status != Core::ERROR_NONE)
                {
                    std::string errorMsg = "COM-RPC returned error " + std::to_string(status) + " (" + std::string(Core::ErrorToString(status)) + ")";
                    TEST_LOG("Err: %s", errorMsg.c_str());
                }
                signalled = notification.WaitForRequestStatus(JSON_TIMEOUT,UserSettings_OnPreferredClosedCaptionServiceChanged);
                EXPECT_TRUE(signalled & UserSettings_OnPreferredClosedCaptionServiceChanged);

                status = m_usersettingsplugin->GetPreferredClosedCaptionService(getStringValue);
                EXPECT_EQ(getStringValue, "CC3");
                EXPECT_EQ(status,Core::ERROR_NONE);
                if (status != Core::ERROR_NONE)
                {
                    std::string errorMsg = "COM-RPC returned error " + std::to_string(status) + " (" + std::string(Core::ErrorToString(status)) + ")";
                    TEST_LOG("Err: %s", errorMsg.c_str());
                }

                m_usersettingsplugin->Unregister(&notification);
                m_usersettingsplugin->Release();
            }
            else
            {
                TEST_LOG("m_usersettingsplugin is NULL");
            }
            m_controller_usersettings->Release();
        }
        else
        {
            TEST_LOG("m_controller_usersettings is NULL");
        }
    }
}

