/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2022 RDK Management
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

#include "../Module.h"
#include "secure_storage.grpc.pb.h"
#include <grpcpp/create_channel.h>
#include <interfaces/IStore2.h>
#ifdef WITH_SYSMGR
#include <libIBus.h>
#include <sysMgr.h>
#endif

namespace WPEFramework {
namespace Plugin {
    namespace Grpc {

        class Store2 : public Exchange::IStore2 {
        private:
            Store2(const Store2&) = delete;
            Store2& operator=(const Store2&) = delete;

        public:
            Store2()
                : Store2(getenv(URI_ENV))
            {
            }
            Store2(const string& uri)
                : IStore2()
                , _uri(uri)
            {
#ifdef WITH_SYSMGR
                IARM_Bus_Init(IARM_INIT_NAME);
                IARM_Bus_Connect();
#endif
                Open();
            }
            ~Store2() override = default;

        private:
            void Open()
            {
                std::shared_ptr<::grpc::ChannelInterface> channel;
                if ((_uri.find("localhost") == string::npos) && (_uri.find("0.0.0.0") == string::npos)) {
                    channel = grpc::CreateChannel(
                        _uri,
                        grpc::CompositeChannelCredentials(
                            grpc::SslCredentials(grpc::SslCredentialsOptions()),
                            grpc::AccessTokenCredentials("")));
                } else {
                    channel = grpc::CreateChannel(_uri, grpc::InsecureChannelCredentials());
                }
                _stub = ::distp::gateway::secure_storage::v1::SecureStorageService::NewStub(channel);
            }

        public:
            uint32_t Register(INotification* notification) override
            {
                Core::SafeSyncType<Core::CriticalSection> lock(_clientLock);

                ASSERT(std::find(_clients.begin(), _clients.end(), notification) == _clients.end());

                notification->AddRef();
                _clients.push_back(notification);

                return Core::ERROR_NONE;
            }
            uint32_t Unregister(INotification* notification) override
            {
                Core::SafeSyncType<Core::CriticalSection> lock(_clientLock);

                std::list<INotification*>::iterator
                    index(std::find(_clients.begin(), _clients.end(), notification));

                ASSERT(index != _clients.end());

                if (index != _clients.end()) {
                    notification->Release();
                    _clients.erase(index);
                }

                return Core::ERROR_NONE;
            }

            uint32_t SetValue(const ScopeType scope, const string& ns, const string& key, const string& value, const uint32_t ttl) override
            {
                ASSERT(scope == ScopeType::ACCOUNT);

                uint32_t result;

                grpc::ClientContext context;
                ::distp::gateway::secure_storage::v1::UpdateValueRequest request;
                auto v = new ::distp::gateway::secure_storage::v1::Value();
                v->set_value(value);
                if (ttl != 0) {
                    auto t = new google::protobuf::Duration();
                    t->set_seconds(ttl);
                    v->set_allocated_ttl(t);
                }
                auto k = new ::distp::gateway::secure_storage::v1::Key();
                k->set_app_id(ns);
                k->set_key(key);
                k->set_scope(::distp::gateway::secure_storage::v1::Scope::SCOPE_ACCOUNT);
                v->set_allocated_key(k);
                request.set_allocated_value(v);
                ::distp::gateway::secure_storage::v1::UpdateValueResponse response;
                auto status = _stub->UpdateValue(&context, request, &response);

                if (status.ok()) {
                    OnValueChanged(ns, key, value);
                    result = Core::ERROR_NONE;
                } else {
                    OnError(__FUNCTION__, status);
                    result = Core::ERROR_GENERAL;
                }

                return result;
            }
            uint32_t GetValue(const ScopeType scope, const string& ns, const string& key, string& value, uint32_t& ttl) override
            {
                ASSERT(scope == ScopeType::ACCOUNT);

                uint32_t result;

                grpc::ClientContext context;
                ::distp::gateway::secure_storage::v1::GetValueRequest request;
                auto k = new ::distp::gateway::secure_storage::v1::Key();
                k->set_app_id(ns);
                k->set_key(key);
                k->set_scope(::distp::gateway::secure_storage::v1::Scope::SCOPE_ACCOUNT);
                request.set_allocated_key(k);
                ::distp::gateway::secure_storage::v1::GetValueResponse response;
                auto status = _stub->GetValue(&context, request, &response);

                if (status.ok() && response.has_value()) {
                    auto v = response.value();
                    if (v.has_ttl()) {
                        value = v.value();
                        ttl = v.ttl().seconds();
                        result = Core::ERROR_NONE;
                    } else if (v.has_expire_time()) {
#ifdef WITH_SYSMGR
                        IARM_Bus_SYSMgr_GetSystemStates_Param_t param;
                        if ((IARM_Bus_Call(IARM_BUS_SYSMGR_NAME, IARM_BUS_SYSMGR_API_GetSystemStates, &param, sizeof(param)) != IARM_RESULT_SUCCESS)
                            || !param.time_source.state) {
                            return Core::ERROR_PENDING_CONDITIONS;
                        }
#endif
                        value = v.value();
                        ttl = v.expire_time().seconds() - Core::Time::Now().Ticks() / Core::Time::TicksPerMillisecond / 1000;
                        result = Core::ERROR_NONE;
                    } else {
                        value = v.value();
                        ttl = 0;
                        result = Core::ERROR_NONE;
                    }
                } else {
                    OnError(__FUNCTION__, status);
                    result = Core::ERROR_GENERAL;
                }

                return result;
            }
            uint32_t DeleteKey(const ScopeType scope, const string& ns, const string& key) override
            {
                ASSERT(scope == ScopeType::ACCOUNT);

                uint32_t result;

                grpc::ClientContext context;
                ::distp::gateway::secure_storage::v1::DeleteValueRequest request;
                auto k = new ::distp::gateway::secure_storage::v1::Key();
                k->set_app_id(ns);
                k->set_key(key);
                k->set_scope(::distp::gateway::secure_storage::v1::Scope::SCOPE_ACCOUNT);
                request.set_allocated_key(k);
                ::distp::gateway::secure_storage::v1::DeleteValueResponse response;
                auto status = _stub->DeleteValue(&context, request, &response);

                if (status.ok()) {
                    result = Core::ERROR_NONE;
                } else {
                    OnError(__FUNCTION__, status);
                    result = Core::ERROR_GENERAL;
                }

                return result;
            }
            uint32_t DeleteNamespace(const ScopeType scope, const string& ns) override
            {
                ASSERT(scope == ScopeType::ACCOUNT);

                uint32_t result;

                grpc::ClientContext context;
                ::distp::gateway::secure_storage::v1::DeleteAllValuesRequest request;
                request.set_app_id(ns);
                request.set_scope(::distp::gateway::secure_storage::v1::Scope::SCOPE_ACCOUNT);
                ::distp::gateway::secure_storage::v1::DeleteAllValuesResponse response;
                auto status = _stub->DeleteAllValues(&context, request, &response);

                if (status.ok()) {
                    result = Core::ERROR_NONE;
                } else {
                    OnError(__FUNCTION__, status);
                    result = Core::ERROR_GENERAL;
                }

                return result;
            }

            BEGIN_INTERFACE_MAP(Store2)
            INTERFACE_ENTRY(IStore2)
            END_INTERFACE_MAP

        private:
            void OnValueChanged(const string& ns, const string& key, const string& value)
            {
                Core::SafeSyncType<Core::CriticalSection> lock(_clientLock);

                std::list<INotification*>::iterator
                    index(_clients.begin());

                while (index != _clients.end()) {
                    (*index)->ValueChanged(ScopeType::DEVICE, ns, key, value);
                    index++;
                }
            }
            void OnError(const char* fn, const grpc::Status& status) const
            {
                TRACE(Trace::Error, (_T("%s grpc error %d %s %s"), fn, status.error_code(), status.error_message().c_str(), status.error_details().c_str()));
            }

        private:
            const string _uri;
            std::unique_ptr<::distp::gateway::secure_storage::v1::SecureStorageService::Stub> _stub;
            std::list<INotification*> _clients;
            Core::CriticalSection _clientLock;
        };

    } // namespace Grpc
} // namespace Plugin
} // namespace WPEFramework
