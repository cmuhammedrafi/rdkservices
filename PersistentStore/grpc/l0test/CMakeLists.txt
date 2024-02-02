# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
# Copyright 2020 RDK Management
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

project(grpcl0test)

set(CMAKE_CXX_STANDARD 11)

include(FetchContent)
FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/609281088cfefc76f9d0ce82e1ff6c30cc3591e5.zip
)
FetchContent_MakeAvailable(googletest)

find_package(WPEFramework)
find_package(${NAMESPACE}Plugins REQUIRED)

add_executable(${PROJECT_NAME}
        ../../Module.cpp
        Store2Test.cpp
)

target_link_libraries(${PROJECT_NAME} PRIVATE
        gmock_main
        ${NAMESPACE}Plugins::${NAMESPACE}Plugins
)

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
        PROTOS ${validate_SOURCE_DIR}/validate/validate.proto ${googleapis_SOURCE_DIR}/google/api/field_behavior.proto ../secure_storage.proto
        PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}
        IMPORT_DIRS ${validate_SOURCE_DIR} ${googleapis_SOURCE_DIR} ..
)
add_custom_target(pb_cc DEPENDS ${PB_CC})
add_dependencies(${PROJECT_NAME} pb_cc)
set_property(SOURCE validate/validate.pb.cc google/api/field_behavior.pb.cc secure_storage.pb.cc PROPERTY GENERATED 1)
target_sources(${PROJECT_NAME} PRIVATE validate/validate.pb.cc google/api/field_behavior.pb.cc secure_storage.pb.cc)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(${PROJECT_NAME} PRIVATE ${Protobuf_LIBRARIES})

find_package(PkgConfig REQUIRED)
pkg_search_module(gRPC REQUIRED grpc)
find_program(GRPC_CPP_PLUGIN grpc_cpp_plugin REQUIRED)
protobuf_generate(
        OUT_VAR GRPC_PB_CC
        PROTOS ../secure_storage.proto
        PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}
        IMPORT_DIRS .. ${validate_SOURCE_DIR} ${googleapis_SOURCE_DIR}
        LANGUAGE grpc
        PLUGIN protoc-gen-grpc=${GRPC_CPP_PLUGIN}
        GENERATE_EXTENSIONS .grpc.pb.h .grpc.pb.cc
)
add_custom_target(grpc_pb_cc DEPENDS ${GRPC_PB_CC})
add_dependencies(${PROJECT_NAME} grpc_pb_cc)
add_dependencies(grpc_pb_cc pb_cc)
set_property(SOURCE secure_storage.grpc.pb.cc PROPERTY GENERATED 1)
target_sources(${PROJECT_NAME} PRIVATE secure_storage.grpc.pb.cc)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(${PROJECT_NAME} PRIVATE grpc++)
target_link_options(${PROJECT_NAME} PRIVATE "LINKER:--copy-dt-needed-entries")

install(TARGETS ${PROJECT_NAME} DESTINATION bin)
