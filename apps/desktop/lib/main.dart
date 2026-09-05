import 'package:flutter/material.dart';
import 'local_agent_api.dart';

void main() => runApp(LocalScaleApp(api: LocalAgentApiClient(FakeLocalAgentTransport())));

class LocalScaleApp extends StatelessWidget {
  const LocalScaleApp({super.key, required this.api});
  final LocalAgentApi api;

  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'LocalScale',
        theme: ThemeData(colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xff6750a4)),
            useMaterial3: true),
        home: ControlPage(api: api),
      );
}

class ControlPage extends StatefulWidget {
  const ControlPage({super.key, required this.api});
  final LocalAgentApi api;
  @override State<ControlPage> createState() => _ControlPageState();
}

class _ControlPageState extends State<ControlPage> {
  ServiceStatus? status;
  String? message;

  @override
  void initState() { super.initState(); _refresh(); }
  Future<void> _refresh() async {
    try { final value = await widget.api.status(); if (mounted) setState(() => status = value); }
    catch (error) { if (mounted) setState(() => message = 'Unable to read LocalScale agent: $error'); }
  }
  Future<void> _run(Future<ServiceStatus> Function() action, String label) async {
    setState(() => message = '$label LocalScale…');
    try { final value = await action(); if (mounted) setState(() { status = value; message = '$label complete'; }); }
    catch (error) { if (mounted) setState(() => message = '$label failed: $error'); }
  }

  @override
  Widget build(BuildContext context) {
    final current = status;
    return Scaffold(
      appBar: AppBar(title: const Text('LocalScale'), actions: [IconButton(onPressed: _refresh, icon: const Icon(Icons.refresh), tooltip: 'Refresh')]),
      body: Center(child: ConstrainedBox(constraints: const BoxConstraints(maxWidth: 900), child: ListView(padding: const EdgeInsets.all(24), children: [
        Text('Control center', style: Theme.of(context).textTheme.headlineMedium),
        const SizedBox(height: 8), const Text('Manage the local LocalScale service.'), const SizedBox(height: 24),
        Card(child: Padding(padding: const EdgeInsets.all(20), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('Mode', style: Theme.of(context).textTheme.titleLarge), const SizedBox(height: 12),
          SegmentedButton<LocalScaleMode>(segments: const [
            ButtonSegment(value: LocalScaleMode.host, label: Text('Host'), icon: Icon(Icons.hub)),
            ButtonSegment(value: LocalScaleMode.cliente, label: Text('Cliente'), icon: Icon(Icons.devices)),
          ], selected: {current?.mode ?? LocalScaleMode.cliente}, onSelectionChanged: (selection) => _run(() => widget.api.setMode(selection.first), 'Mode update')),
          const SizedBox(height: 8), const Text('Host publishes an Onion service. Cliente connects outbound.'),
        ]))), const SizedBox(height: 16),
        Card(child: Padding(padding: const EdgeInsets.all(20), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('Service status', style: Theme.of(context).textTheme.titleLarge), const SizedBox(height: 12),
          Row(children: [Icon(Icons.circle, size: 14, color: _stateColor(current?.state)), const SizedBox(width: 8), Text(_stateLabel(current?.state))]),
          const SizedBox(height: 16), TextFormField(initialValue: current?.onionEndpoint ?? '', readOnly: true, decoration: const InputDecoration(labelText: 'Onion endpoint', hintText: 'Available when running as Host', border: OutlineInputBorder())),
          const SizedBox(height: 16), Wrap(spacing: 12, runSpacing: 8, children: [
            FilledButton.icon(onPressed: () => _run(widget.api.start, 'Start'), icon: const Icon(Icons.play_arrow), label: const Text('Start')),
            OutlinedButton.icon(onPressed: () => _run(widget.api.stop, 'Stop'), icon: const Icon(Icons.stop), label: const Text('Stop')),
            OutlinedButton.icon(onPressed: () => _run(widget.api.sync, 'Sync'), icon: const Icon(Icons.sync), label: const Text('Sync')),
          ]), if (message != null) ...[const SizedBox(height: 12), Text(message!, key: const Key('status-message'))],
        ]))),
      ]))),
    );
  }
  Color _stateColor(ServiceState? state) => state == ServiceState.running ? Colors.green : Colors.orange;
  String _stateLabel(ServiceState? state) => switch (state) { ServiceState.running => 'Running', ServiceState.starting => 'Starting', ServiceState.stopping => 'Stopping', ServiceState.error => 'Error', _ => 'Stopped' };
}
