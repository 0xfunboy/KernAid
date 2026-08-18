# Rescue OpenAI executor

This crate is the one-request, socket-activated application-plane boundary for
the Rescue OpenAI provider:

- `provider.status` authenticates the root Rescue vault over its local
  `SOCK_SEQPACKET` socket and returns only vault and OpenAI credential presence;
- `provider.openai.diagnose` prepares the already-audited fixed Responses body,
  borrows one API-key pipe from the vault as the exact Agent, consumes its
  declared bytes and EOF into zeroizing owned storage, and performs one
  synchronous TLS exchange;
- the compiled shipping destination is only `api.openai.com:443`, with SNI and `Host`
  fixed to `api.openai.com`, `POST /v1/responses`, HTTP/1.1 ALPN, compiled WebPKI
  roots, no redirect, and no URL, model, tool, command, proxy, trust-root, or
  environment override;
- the opaque request body comes only from `prepare_openai_exchange`, and the
  bounded HTTP response is accepted only after strict framing and
  `decode_openai_response` validation;
- one accepted connection receives at most one packet and emits at most one
  correlated response before the process exits.

The binary writes neither standard output nor standard error. The systemd
service supplies the accepted local socket on standard input, null-routes both
output streams, has a private network namespace, is restricted to `AF_UNIX`,
has an empty capability set and one task, and makes itself non-dumpable before
receiving the packet. TLS runs end-to-end from that executor over a dedicated
local Unix stream served by a separate, secret-blind
`systemd-socket-proxyd`; the proxy has no vault or provider-client group and can
reach only the immutable upstream destination. The authenticated vault control
socket remains open through the HTTPS exchange and local response. Handoff,
HTTPS, and outer process deadlines are 20, 110, and 145 seconds respectively.
The API key is not logged or deliberately duplicated, though rustls necessarily
buffers protocol plaintext internally during the exchange.

In Rescue, Desk's fixed same-origin loopback endpoint is served by the shipping
Python UI server, which relays one bounded opaque frame to the executor's
AF_UNIX socket. The privileged BIOS/UEFI lifecycle qualifies an exact image
revision only when both jobs pass; its relay probe keeps egress inactive and
therefore does not exercise Chromium rendering, live TLS, a real account or
physical media.
