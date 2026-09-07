# LocalScale agent

The protocol crate under `agent/protocol/` defines the versioned message parsing,
role and bounds validation, and an explicit non-cryptographic security boundary.
It is a skeleton for the LocalScale agent; transport, authentication, and
platform integrations remain separate implementation work.
