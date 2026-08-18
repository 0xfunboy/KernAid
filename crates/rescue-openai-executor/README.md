# Rescue OpenAI executor scaffold

This crate is the one-request, socket-activated application-plane boundary for
the Rescue OpenAI provider. The shipping scaffold is deliberately incapable of
provider execution:

- `provider.status` authenticates the root Rescue vault over its local
  `SOCK_SEQPACKET` socket and returns only vault and OpenAI credential presence;
- `provider.openai.diagnose` returns `credential_unavailable` without opening
  the vault socket;
- no provider credential descriptor, network address, or environment setting
  is accepted by the executor; a diagnosis corpus enters only the existing
  bounded strict parser and is never logged, persisted, forwarded, or sent to
  a network;
- one accepted connection receives at most one packet and emits at most one
  correlated response before the process exits.

The binary writes neither standard output nor standard error. The systemd
service supplies the accepted local socket on standard input, null-routes both
output streams, has no host or externally routed network interface, and is
restricted to `AF_UNIX` with an empty capability set. The process also makes
itself non-dumpable before receiving the packet.
