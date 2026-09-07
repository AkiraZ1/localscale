export 'local_agent_transport_stub.dart'
    if (dart.library.html) 'local_agent_transport_web.dart'
    if (dart.library.io) 'local_agent_transport_io.dart';
