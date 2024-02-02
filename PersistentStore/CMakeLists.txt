# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
# Copyright 2022 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.14)

project(PersistentStore)

set(CMAKE_CXX_STANDARD 11)

find_package(WPEFramework)
set(MODULE_NAME "${NAMESPACE}${PROJECT_NAME}")

set(PLUGIN_PERSISTENTSTORE_MODE "Off" CACHE STRING "Controls if the plugin should run in its own process, in process or remote")
set(PLUGIN_PERSISTENTSTORE_URI "ss.eu.prod.developer.comcast.com:443" CACHE STRING "Account scope endpoint")
set(PLUGIN_PERSISTENTSTORE_PATH "/opt/secure/persistent/rdkservicestore" CACHE STRING "Path")
set(PLUGIN_PERSISTENTSTORE_LEGACYPATH "/opt/persistent/rdkservicestore" CACHE STRING "Previously used path")
set(PLUGIN_PERSISTENTSTORE_KEY "" CACHE STRING "Encryption key")
set(PLUGIN_PERSISTENTSTORE_MAXSIZE "1000000" CACHE STRING "For all text data, in bytes")
set(PLUGIN_PERSISTENTSTORE_MAXVALUE "3000" CACHE STRING "For single text data, in bytes")
set(PLUGIN_PERSISTENTSTORE_LIMIT "10000" CACHE STRING "Default for all text data in namespace, in bytes")
set(PLUGIN_PERSISTENTSTORE_STARTUPORDER "" CACHE STRING "To configure startup order of PersistentStore plugin")

find_package(${NAMESPACE}Plugins REQUIRED)
find_package(${NAMESPACE}Definitions REQUIRED)

add_library(${MODULE_NAME} SHARED
        PersistentStore.cpp
        PersistentStoreJsonRpc.cpp
        grpc/Store2.cpp
        sqlite/Store2.cpp
        sqlite/StoreCache.cpp
        sqlite/StoreInspector.cpp
        sqlite/StoreLimit.cpp
        Module.cpp
)

target_link_libraries(${MODULE_NAME} PRIVATE
        ${NAMESPACE}Plugins::${NAMESPACE}Plugins
        ${NAMESPACE}Definitions::${NAMESPACE}Definitions
)

find_package(PkgConfig REQUIRED)
pkg_search_module(SQLITE REQUIRED sqlite3)
target_link_libraries(${MODULE_NAME} PRIVATE ${SQLITE_LIBRARIES})

find_library(IARMBUS_LIBRARIES NAMES IARMBus)
if (IARMBUS_LIBRARIES)
    find_path(IARMBUS_INCLUDE_DIRS NAMES libIBus.h PATH_SUFFIXES rdk/iarmbus REQUIRED)
    find_path(IARMSYS_INCLUDE_DIRS NAMES sysMgr.h PATH_SUFFIXES rdk/iarmmgrs/sysmgr REQUIRED)
    target_include_directories(${MODULE_NAME} PRIVATE ${IARMBUS_INCLUDE_DIRS} ${IARMSYS_INCLUDE_DIRS})
    target_link_libraries(${MODULE_NAME} PRIVATE ${IARMBUS_LIBRARIES})
    add_definitions(-DWITH_SYSMGR)
endif ()

include(FetchContent)
FetchContent_Declare(
        validate
        GIT_REPOSITORY https://github.com/bufbuild/protoc-gen-validate.git
        GIT_TAG v1.0.4
)
FetchContent_Declare(
        googleapis
        GIT_REPOSITORY https://github.com/googleapis/googleapis.git
        GIT_TAG master
)
FetchContent_MakeAvailable(validate googleapis)

find_package(Protobuf REQUIRED)
protobuf_generate(
        OUT_VAR PB_CC
        PROTOS ${validate_SOURCE_DIR}/validate/validate.proto ${googleapis_SOURCE_DIR}/google/api/field_behavior.proto grpc/secure_storage.proto
        PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}
        IMPORT_DIRS ${validate_SOURCE_DIR} ${googleapis_SOURCE_DIR} grpc
)
add_custom_target(pb_cc DEPENDS ${PB_CC})
add_dependencies(${MODULE_NAME} pb_cc)
set_property(SOURCE validate/validate.pb.cc google/api/field_behavior.pb.cc grpc/secure_storage.pb.cc PROPERTY GENERATED 1)
target_sources(${MODULE_NAME} PRIVATE validate/validate.pb.cc google/api/field_behavior.pb.cc grpc/secure_storage.pb.cc)
target_include_directories(${MODULE_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR}/grpc)
target_link_libraries(${MODULE_NAME} PRIVATE ${Protobuf_LIBRARIES})

find_package(PkgConfig REQUIRED)
pkg_search_module(gRPC REQUIRED grpc)
find_program(GRPC_CPP_PLUGIN grpc_cpp_plugin REQUIRED)
protobuf_generate(
        OUT_VAR GRPC_PB_CC
        PROTOS grpc/secure_storage.proto
        PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}
        IMPORT_DIRS grpc ${validate_SOURCE_DIR} ${googleapis_SOURCE_DIR}
        LANGUAGE grpc
        PLUGIN protoc-gen-grpc=${GRPC_CPP_PLUGIN}
        GENERATE_EXTENSIONS .grpc.pb.h .grpc.pb.cc
)
add_custom_target(grpc_pb_cc DEPENDS ${GRPC_PB_CC})
add_dependencies(${MODULE_NAME} grpc_pb_cc)
add_dependencies(grpc_pb_cc pb_cc)
set_property(SOURCE grpc/secure_storage.grpc.pb.cc PROPERTY GENERATED 1)
target_sources(${MODULE_NAME} PRIVATE grpc/secure_storage.grpc.pb.cc)
target_include_directories(${MODULE_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR}/grpc)
target_link_libraries(${MODULE_NAME} PRIVATE grpc++)
target_link_options(${MODULE_NAME} PRIVATE "LINKER:--copy-dt-needed-entries")

install(TARGETS ${MODULE_NAME}
        DESTINATION lib/${STORAGE_DIRECTORY}/plugins)

write_config()
