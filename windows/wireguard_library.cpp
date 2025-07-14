#include "wireguard_library.h"

#include <stdexcept>

namespace wireguard_dart {

std::unique_ptr<WireguardLibrary> WireguardLibrary::Create() {
  auto library = std::unique_ptr<WireguardLibrary>(new WireguardLibrary());
  if (!library->LoadLibrary()) {
    return nullptr;
  }
  return library;
}

WireguardLibrary::~WireguardLibrary() {
  if (dll_handle_) {
    FreeLibrary(dll_handle_);
    dll_handle_ = nullptr;
  }
}

bool WireguardLibrary::LoadLibrary() {
  // Try to load the WireGuard DLL
  dll_handle_ = ::LoadLibraryW(L"wireguard.dll");
  if (!dll_handle_) {
    return false;
  }

  try {
    LoadFunctions();
    return true;
  } catch (...) {
    FreeLibrary(dll_handle_);
    dll_handle_ = nullptr;
    return false;
  }
}

void WireguardLibrary::LoadFunctions() {
  // Load all required function pointers
  create_adapter_ = reinterpret_cast<CreateAdapterFunc>(GetProcAddress(dll_handle_, "WireGuardCreateAdapter"));
  if (!create_adapter_) {
    throw std::runtime_error("Failed to load WireGuardCreateAdapter");
  }

  open_adapter_ = reinterpret_cast<OpenAdapterFunc>(GetProcAddress(dll_handle_, "WireGuardOpenAdapter"));
  if (!open_adapter_) {
    throw std::runtime_error("Failed to load WireGuardOpenAdapter");
  }

  close_adapter_ = reinterpret_cast<CloseAdapterFunc>(GetProcAddress(dll_handle_, "WireGuardCloseAdapter"));
  if (!close_adapter_) {
    throw std::runtime_error("Failed to load WireGuardCloseAdapter");
  }

  delete_driver_ = reinterpret_cast<DeleteDriverFunc>(GetProcAddress(dll_handle_, "WireGuardDeleteDriver"));
  if (!delete_driver_) {
    throw std::runtime_error("Failed to load WireGuardDeleteDriver");
  }

  get_adapter_luid_ = reinterpret_cast<GetAdapterLuidFunc>(GetProcAddress(dll_handle_, "WireGuardGetAdapterLUID"));
  if (!get_adapter_luid_) {
    throw std::runtime_error("Failed to load WireGuardGetAdapterLUID");
  }

  get_running_driver_version_ =
      reinterpret_cast<GetRunningDriverVersionFunc>(GetProcAddress(dll_handle_, "WireGuardGetRunningDriverVersion"));
  if (!get_running_driver_version_) {
    throw std::runtime_error("Failed to load WireGuardGetRunningDriverVersion");
  }

  set_logger_ = reinterpret_cast<SetLoggerFunc>(GetProcAddress(dll_handle_, "WireGuardSetLogger"));
  if (!set_logger_) {
    throw std::runtime_error("Failed to load WireGuardSetLogger");
  }

  set_adapter_logging_ =
      reinterpret_cast<SetAdapterLoggingFunc>(GetProcAddress(dll_handle_, "WireGuardSetAdapterLogging"));
  if (!set_adapter_logging_) {
    throw std::runtime_error("Failed to load WireGuardSetAdapterLogging");
  }

  set_adapter_state_ = reinterpret_cast<SetAdapterStateFunc>(GetProcAddress(dll_handle_, "WireGuardSetAdapterState"));
  if (!set_adapter_state_) {
    throw std::runtime_error("Failed to load WireGuardSetAdapterState");
  }

  get_adapter_state_ = reinterpret_cast<GetAdapterStateFunc>(GetProcAddress(dll_handle_, "WireGuardGetAdapterState"));
  if (!get_adapter_state_) {
    throw std::runtime_error("Failed to load WireGuardGetAdapterState");
  }

  set_configuration_ = reinterpret_cast<SetConfigurationFunc>(GetProcAddress(dll_handle_, "WireGuardSetConfiguration"));
  if (!set_configuration_) {
    throw std::runtime_error("Failed to load WireGuardSetConfiguration");
  }

  get_configuration_ = reinterpret_cast<GetConfigurationFunc>(GetProcAddress(dll_handle_, "WireGuardGetConfiguration"));
  if (!get_configuration_) {
    throw std::runtime_error("Failed to load WireGuardGetConfiguration");
  }
}

}  // namespace wireguard_dart
