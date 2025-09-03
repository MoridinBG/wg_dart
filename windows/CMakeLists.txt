# The Flutter tooling requires that developers have a version of Visual Studio
# installed that includes CMake 3.14 or later. You should not increase this
# version, as doing so will cause the plugin to fail to compile for some
# customers of the plugin.
cmake_minimum_required(VERSION 3.14)

# get_cmake_property(_variableNames VARIABLES)
# list (SORT _variableNames)
# foreach (_variableName ${_variableNames})
#     message(STATUS "${_variableName}=${${_variableName}}")
# endforeach()

# Project-level configuration.
set(PROJECT_NAME "wireguard_dart")
project(${PROJECT_NAME} LANGUAGES CXX)

# This value is used when generating builds using this plugin, so it must
# not be changed
set(PLUGIN_NAME "wireguard_dart_plugin")

# Any new source files that you add to the plugin should be added here.
list(APPEND PLUGIN_SOURCES
  "wireguard_dart_plugin.cpp"
  "wireguard_dart_plugin.h"
  "key_generator.cpp"
  "key_generator.h"
  "connection_status.h"
  "connection_status.cpp"
  "network_adapter_status_observer.h"
  "network_adapter_status_observer.cpp"
  "utils.cpp"
  "utils.h"
  "wireguard_library.cpp"
  "wireguard_library.h"
  "wireguard_adapter.cpp"
  "wireguard_adapter.h"
  "wireguard_config_parser.cpp"
  "wireguard_config_parser.h"
  "wireguard_network_config.cpp"
  "wireguard_network_config.h"
)

# Define the plugin library target. Its name must not be changed (see comment
# on PLUGIN_NAME above).
add_library(${PLUGIN_NAME} SHARED
  "include/wireguard_dart/wireguard_dart_plugin_c_api.h"
  "wireguard_dart_plugin_c_api.cpp"
  ${PLUGIN_SOURCES}
)

# Apply a standard set of build settings that are configured in the
# application-level CMakeLists.txt. This can be removed for plugins that want
# full control over build settings.
apply_standard_settings(${PLUGIN_NAME})

# Symbols are hidden by default to reduce the chance of accidental conflicts
# between plugins. This should not be removed; any symbols that should be
# exported should be explicitly exported with the FLUTTER_PLUGIN_EXPORT macro.
set_target_properties(${PLUGIN_NAME} PROPERTIES
  CXX_VISIBILITY_PRESET hidden)
target_compile_definitions(${PLUGIN_NAME} PRIVATE FLUTTER_PLUGIN_IMPL)

# Add UTF-8 support for spdlog
if(MSVC)
  target_compile_options(${PLUGIN_NAME} PRIVATE /utf-8)
endif()

# Source include directories and library dependencies. Add any plugin-specific
# dependencies here.
add_subdirectory(external)
target_link_libraries(${PLUGIN_NAME} PRIVATE base64)

add_compile_definitions(WIN32_LEAN_AND_MEAN) # for Wireguard winsock/windows conflict

add_library(wireguard SHARED IMPORTED GLOBAL)
set_target_properties(wireguard PROPERTIES
    IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/lib/wireguard/amd64/wireguard.dll"
)
target_include_directories(wireguard INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/lib/wireguard/include")
target_link_libraries(${PLUGIN_NAME} PRIVATE wireguard)

# Add spdlog as a header-only library
add_library(spdlog INTERFACE)
target_include_directories(spdlog INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/lib")
target_link_libraries(${PLUGIN_NAME} PRIVATE spdlog)

# Disable warnings as errors for spdlog unreachable code warnings
if(MSVC)
  target_compile_options(${PLUGIN_NAME} PRIVATE /wd4702) # disable unreachable code warning
endif()

target_include_directories(${PLUGIN_NAME} INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/lib/tunnel/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/lib/wireguard/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/lib"
)
target_link_libraries(${PLUGIN_NAME} PRIVATE flutter flutter_wrapper_plugin ws2_32 iphlpapi)

# List of absolute paths to libraries that should be bundled with the plugin.
# This list could contain prebuilt libraries, or libraries created by an
# external build triggered from this build file.
set(wireguard_dart_bundled_libraries
  "${CMAKE_CURRENT_SOURCE_DIR}/lib/wireguard/amd64/wireguard.dll"
  PARENT_SCOPE
)
