# tdsh — a minimal TDS client in C

A hand-written client for Microsoft SQL Server's wire protocol (TDS), built from
scratch in C with no database driver. No FreeTDS, no ODBC — just sockets, OpenSSL,
and the [MS-TDS] specification. It speaks pre-login, negotiates TLS *inside* TDS
packets, and authenticates with a dynamically built LOGIN7 packet.

This is a learning project: the goal was to understand the protocol down to the
byte, not to ship a production driver.

## What it does

1. Opens a TCP connection to a SQL Server instance.
2. Sends a **pre-login** packet and reads the server's encryption requirement.
3. Performs a **TLS handshake wrapped inside TDS packets** — the unusual part of
   TDS, where each TLS handshake message is carried as the payload of a `0x12`
   TDS packet. OpenSSL is driven manually through memory BIOs rather than letting
   it own the socket.
4. Builds and sends a **LOGIN7** packet over the encrypted channel: fixed header,
   a dynamically computed offset/length table, UTF-16LE field data, and the
   password obfuscated with the TDS nibble-swap + XOR 0xA5 scheme.
5. Parses the login response and confirms a **LOGINACK** token.

## Build

Requires a C compiler, OpenSSL, and (on Windows) Winsock. Developed with MSYS2
UCRT64 on Windows.

```
gcc -Wall tdsh.c -o tdsh.exe -lws2_32 -lssl -lcrypto
```

On Linux the socket layer would use POSIX sockets instead of Winsock (the
`#ifdef`-guarded part); the TDS/TLS logic is portable.

## Usage

```
./tdsh.exe <host> <port> <username> <password> <database>
```

Example:

```
./tdsh.exe 192.168.1.50 1433 sa MyPassword master
```

A successful run ends with `LOGINACK found — login successful!`.

## How it is structured

The code is one file, split into single-responsibility functions:

| Function | Responsibility |
|---|---|
| `tcp_connect` | Open the TCP socket |
| `tds_send_prelogin` | Send pre-login, drain the response |
| `ssl_setup` | Create the OpenSSL context + memory BIOs |
| `tds_flush_outgoing` | Pull TLS bytes from OpenSSL, wrap in TDS, send (handshake) |
| `tds_feed_incoming` | Read a TDS packet, strip its header, feed TLS into OpenSSL |
| `tds_tls_handshake` | Drive `SSL_connect` by hand across the BIO bridge |
| `tds_send_app_data` | Send post-handshake data (TDS header already inside the TLS payload) |
| `write_field` | Write one LOGIN7 offset/length pair and its UTF-16LE data |
| `ascii_to_utf16le` | Convert a string to UTF-16LE |
| `apply_transform_utf16le` | TDS password obfuscation (nibble-swap + XOR 0xA5) |
| `Login7` | Build the LOGIN7 packet and authenticate |

## Notes & limitations

This is intentionally minimal and lab-oriented:

- **Certificate verification is disabled** (`SSL_VERIFY_NONE`) to accept the
  self-signed certificate a default SQL Server presents. Do not use this against
  a server you don't control without adding proper verification.
- **One TDS packet per `recv` is assumed.** A production client must reassemble
  packets using the length field in the TDS header, since TCP does not preserve
  message boundaries.
- **The login response is read as plaintext TDS.** With this server's encryption
  mode, only the login exchange is encrypted; the post-login response arrives
  unencrypted, so it is parsed directly rather than through `SSL_read`.
- ASCII-only field values are assumed for username/password/database.

## What's next

- Send a SQL batch (`0x01` packet) and parse the result token stream
  (COLMETADATA → ROW → DONE).
- Render result rows as an aligned table.
- A REPL loop for interactive queries.

## Why

SSMS round-trips get tiring. The longer-term aim is a `psql`-style terminal
client for SQL Server. This client is the protocol foundation for that.

## Reference

- **[MS-TDS]: Tabular Data Stream Protocol** — Microsoft's official wire-format spec.
- **Beej's Guide to Network Programming** — for the socket layer.
- OpenSSL `SSL_do_handshake` / memory BIO documentation — for driving TLS by hand.