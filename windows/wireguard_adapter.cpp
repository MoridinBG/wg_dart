#include "wireguard_adapter.h"

#include <stdexcept>

namespace wireguard_dart {

std::unique_ptr<WireguardAdapter> WireguardAdapter::Create(const std::shared_ptr<WireguardLibrary>& library,
                                                           const std::wstring& name, const std::wstring& tunnel_type) {
  if (!library || !library->IsLoaded()) {
    return nullptr;
  }

  auto adapter = std::unique_ptr<WireguardAdapter>(new WireguardAdapter(library, name));

  adapter->adapter_handle_ = library->CreateAdapter()(name.c_str(), tunnel_type.c_str(),
                                                      nullptr  // Let system choose GUID
  );

  if (!adapter->adapter_handle_) {
    return nullptr;
  }

  return adapter;
}

std::unique_ptr<WireguardAdapter> WireguardAdapter::Open(const std::shared_ptr<WireguardLibrary>& library,
                                                         const std::wstring& name) {
  if (!library || !library->IsLoaded()) {
    return nullptr;
  }

  auto adapter = std::unique_ptr<WireguardAdapter>(new WireguardAdapter(library, name));

  adapter->adapter_handle_ = library->OpenAdapter()(name.c_str());

  if (!adapter->adapter_handle_) {
    return nullptr;
  }

  return adapter;
}

WireguardAdapter::WireguardAdapter(const std::shared_ptr<WireguardLibrary>& library, const std::wstring& name)
    : library_(library), name_(name) {}

WireguardAdapter::~WireguardAdapter() {
  if (adapter_handle_ && library_ && library_->IsLoaded()) {
    library_->CloseAdapter()(adapter_handle_);
    adapter_handle_ = nullptr;
  }
}

bool WireguardAdapter::SetState(WIREGUARD_ADAPTER_STATE state) {
  if (!IsValid() || !library_->IsLoaded()) {
    return false;
  }

  return library_->SetAdapterState()(adapter_handle_, state) != FALSE;
}

WIREGUARD_ADAPTER_STATE WireguardAdapter::GetState() const {
  if (!IsValid() || !library_->IsLoaded()) {
    return WIREGUARD_ADAPTER_STATE_DOWN;
  }

  WIREGUARD_ADAPTER_STATE state;
  if (library_->GetAdapterState()(adapter_handle_, &state)) {
    return state;
  }

  return WIREGUARD_ADAPTER_STATE_DOWN;
}

bool WireguardAdapter::SetConfiguration(const WIREGUARD_INTERFACE* config, DWORD bytes) {
  if (!IsValid() || !library_->IsLoaded() || !config) {
    return false;
  }

  return library_->SetConfiguration()(adapter_handle_, config, bytes) != FALSE;
}

bool WireguardAdapter::GetConfiguration(WIREGUARD_INTERFACE* config, DWORD* bytes) const {
  if (!IsValid() || !library_->IsLoaded() || !config || !bytes) {
    return false;
  }

  return library_->GetConfiguration()(adapter_handle_, config, bytes) != FALSE;
}

bool WireguardAdapter::GetLUID(NET_LUID* luid) const {
  if (!IsValid() || !library_->IsLoaded() || !luid) {
    return false;
  }

  library_->GetAdapterLuid()(adapter_handle_, luid);
  return true;
}

bool WireguardAdapter::SetLogging(WIREGUARD_ADAPTER_LOG_STATE log_state) {
  if (!IsValid() || !library_->IsLoaded()) {
    return false;
  }

  return library_->SetAdapterLogging()(adapter_handle_, log_state) != FALSE;
}

}  // namespace wireguard_dart
