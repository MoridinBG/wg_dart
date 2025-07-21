#pragma once

#include <windows.h>

#include <functional>
#include <memory>

#include "wireguard.h"

namespace wireguard_dart {

/**
 * Manages the WireGuard DLL loading and function pointers.
 * Implements singleton pattern to ensure only one DLL instance is loaded.
 */
class WireguardLibrary {
 public:
  // Function pointer types from the WireGuard library
  using CreateAdapterFunc = WIREGUARD_CREATE_ADAPTER_FUNC*;
  using OpenAdapterFunc = WIREGUARD_OPEN_ADAPTER_FUNC*;
  using CloseAdapterFunc = WIREGUARD_CLOSE_ADAPTER_FUNC*;
  using DeleteDriverFunc = WIREGUARD_DELETE_DRIVER_FUNC*;
  using GetAdapterLuidFunc = WIREGUARD_GET_ADAPTER_LUID_FUNC*;
  using GetRunningDriverVersionFunc = WIREGUARD_GET_RUNNING_DRIVER_VERSION_FUNC*;
  using SetLoggerFunc = WIREGUARD_SET_LOGGER_FUNC*;
  using SetAdapterLoggingFunc = WIREGUARD_SET_ADAPTER_LOGGING_FUNC*;
  using SetAdapterStateFunc = WIREGUARD_SET_ADAPTER_STATE_FUNC*;
  using GetAdapterStateFunc = WIREGUARD_GET_ADAPTER_STATE_FUNC*;
  using SetConfigurationFunc = WIREGUARD_SET_CONFIGURATION_FUNC*;
  using GetConfigurationFunc = WIREGUARD_GET_CONFIGURATION_FUNC*;

  static std::unique_ptr<WireguardLibrary> Create();
  ~WireguardLibrary();

  // Disable copy and move
  WireguardLibrary(const WireguardLibrary&) = delete;
  WireguardLibrary& operator=(const WireguardLibrary&) = delete;
  WireguardLibrary(WireguardLibrary&&) = delete;
  WireguardLibrary& operator=(WireguardLibrary&&) = delete;

  // Function accessors
  CreateAdapterFunc CreateAdapter() const { return create_adapter_; }
  OpenAdapterFunc OpenAdapter() const { return open_adapter_; }
  CloseAdapterFunc CloseAdapter() const { return close_adapter_; }
  DeleteDriverFunc DeleteDriver() const { return delete_driver_; }
  GetAdapterLuidFunc GetAdapterLuid() const { return get_adapter_luid_; }
  GetRunningDriverVersionFunc GetRunningDriverVersion() const { return get_running_driver_version_; }
  SetLoggerFunc SetLogger() const { return set_logger_; }
  SetAdapterLoggingFunc SetAdapterLogging() const { return set_adapter_logging_; }
  SetAdapterStateFunc SetAdapterState() const { return set_adapter_state_; }
  GetAdapterStateFunc GetAdapterState() const { return get_adapter_state_; }
  SetConfigurationFunc SetConfiguration() const { return set_configuration_; }
  GetConfigurationFunc GetConfiguration() const { return get_configuration_; }

  bool IsLoaded() const { return dll_handle_ != nullptr; }

 private:
  WireguardLibrary() = default;
  bool LoadLibrary();
  void LoadFunctions();

  HMODULE dll_handle_ = nullptr;

  // Function pointers
  CreateAdapterFunc create_adapter_ = nullptr;
  OpenAdapterFunc open_adapter_ = nullptr;
  CloseAdapterFunc close_adapter_ = nullptr;
  DeleteDriverFunc delete_driver_ = nullptr;
  GetAdapterLuidFunc get_adapter_luid_ = nullptr;
  GetRunningDriverVersionFunc get_running_driver_version_ = nullptr;
  SetLoggerFunc set_logger_ = nullptr;
  SetAdapterLoggingFunc set_adapter_logging_ = nullptr;
  SetAdapterStateFunc set_adapter_state_ = nullptr;
  GetAdapterStateFunc get_adapter_state_ = nullptr;
  SetConfigurationFunc set_configuration_ = nullptr;
  GetConfigurationFunc get_configuration_ = nullptr;
};

}  // namespace wireguard_dart
