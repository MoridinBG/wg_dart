import 'package:wireguard_dart/connection_status.dart';

class AdapterStatus {
  final int luid;
  final ConnectionStatus status;

  const AdapterStatus(this.luid, this.status);

  @override
  String toString() => 'AdapterStatus(luid: $luid, status: $status)';

  @override
  bool operator ==(Object other) =>
      identical(this, other) || other is AdapterStatus && runtimeType == other.runtimeType && luid == other.luid && status == other.status;

  @override
  int get hashCode => luid.hashCode ^ status.hashCode;
}
