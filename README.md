# tdsh — a minimal TDS client in C

A hand-written client for Microsoft SQL Server's wire protocol (TDS), built from
scratch in C with no database driver. No FreeTDS, no ODBC — just sockets, OpenSSL,
and the [MS-TDS] specification. It speaks pre-login, negotiates TLS *inside* TDS
packets, authenticates with a dynamically built LOGIN7 packet, and then runs
T-SQL from an interactive prompt, rendering result sets as aligned tables — a
`psql`-style terminal client for SQL Server.

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
5. Parses the login response by walking the **token stream** and confirms a
   **LOGINACK** token (surfacing the server's message if an ERROR token appears).
6. Drops into an **interactive REPL**: each line you type is sent as a
   **SQL batch** (`0x01` packet), the response is reassembled across TDS packets,
   its **result token stream** is parsed (`COLMETADATA` → `ROW`/`NBCROW` → `DONE`),
   and rows are printed as an **aligned table**.

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

After `Login Success` you land in the interactive prompt. Type a T-SQL statement,
press Enter, and the result comes back as a coloured box table. `\exit` (or `\q`,
or EOF — `Ctrl+Z` then Enter on Windows) leaves the loop. Every command tdsh
handles itself starts with a backslash; `\help` lists them.

```
Login Success

  tdsh interactive — type T-SQL and press Enter, \help for commands.

tdsh> SELECT name, database_id FROM sys.databases
┌────────┬─────────────┐
│ name   │ database_id │
├────────┼─────────────┤
│ master │           1 │
│ tempdb │           2 │
│ model  │           3 │
│ msdb   │           4 │
└────────┴─────────────┘
(4 rows)

tdsh> \exit
```

Each line is sent as its own batch, so `GO`-style multi-statement buffering is not
needed — separate statements with `;` within a line if you want several at once.

Wide result sets (more columns than fit the terminal) are shown automatically in
an **expanded** layout — one `column | value` line per field, grouped per record,
like psql's `\x`:

```
tdsh> SELECT * FROM ETKINLIK
[ RECORD 1 ]──┼────────────────────────
id            │ 1
ad            │ Bahar Konseri
tarih         │ 2024-04-20
...
```

Long result sets are **paged** a screenful at a time (Enter/Space for the next
page, `q` to stop) so nothing scrolls off unseen.

Meta-commands (all start with `\`): `\help`/`\?` show the command list, `\x`
toggles expanded display on/off (off = auto), `\pager` toggles paging, `\clear`
(or `\cls`) clears the screen, `\exit`/`\q` leaves.

## How it is structured

The code is one file, split into single-responsibility functions:

| Function | Responsibility |
|---|---|
| `tcp_connect` | Open the TCP socket |
| `tds_send_prelogin` | Send pre-login, parse the negotiated encryption mode |
| `ssl_setup` | Create the OpenSSL context + memory BIOs |
| `tds_flush_outgoing` | Pull TLS bytes from OpenSSL, wrap in TDS, send (handshake) |
| `tds_feed_incoming` | Read a TDS packet, strip its header, feed TLS into OpenSSL |
| `tds_tls_handshake` | Drive `SSL_connect` by hand across the BIO bridge |
| `tds_send_app_data` | Send post-handshake data (TDS header already inside the TLS payload) |
| `write_field` | Write one LOGIN7 offset/length pair and its UTF-16LE data |
| `ascii_to_utf16le` | Convert a string to UTF-16LE (bounds-checked) |
| `apply_transform_utf16le` | TDS password obfuscation (nibble-swap + XOR 0xA5) |
| `Login7` | Build the LOGIN7 packet and authenticate |
| `parse_login_response` | Walk the login token stream, confirm LOGINACK, print ERROR |
| `tds_send_message` | Frame a message into TDS packets and send (TLS or plaintext) |
| `tds_read_message` | Reassemble a full TDS message across packets (TLS or plaintext) |
| `parse_type_info` | Decode a column's `TYPE_INFO` from `COLMETADATA` |
| `read_cell` | Read one row value (all length encodings incl. PLP/text) |
| `format_cell` | Format a raw value as text (ints, decimal, dates, strings, …) |
| `parse_result_stream` | Walk the result token stream and render tables |
| `tds_exec` | Send a T-SQL batch and print the result |
| `run_repl` | Interactive read-eval-print loop |

## Result-set support

`parse_result_stream` walks the token stream a query returns and renders each
result set as a table. It handles:

- **Tokens:** `COLMETADATA` (0x81), `ROW` (0xD1), `NBCROW` (0xD2, null-bitmap
  compressed rows), `DONE`/`DONEPROC`/`DONEINPROC`, `RETURNSTATUS`, and the
  variable-length `ERROR`/`INFO`/`ENVCHANGE`/`ORDER`/… tokens.
- **All row length encodings:** fixed-length, byte-length, `USHORT`-length,
  `LONG`-length (text/ntext/image via text pointer), and **PLP** for the
  `MAX` types.
- **Value formatting:** integers, `bit`, `real`/`float`, `money`,
  `decimal`/`numeric` (arbitrary precision via base-10 conversion),
  `date`/`datetime`/`smalldatetime`/`datetime2`/`time`/`datetimeoffset`,
  `uniqueidentifier`, `(n)char`/`(n)varchar`/text, and `binary`/`varbinary` as
  hex. `NULL` is shown as `NULL`. Unknown types stop the parse rather than
  misalign the stream.

## Notes & limitations

This is intentionally minimal and lab-oriented:

- **Certificate verification is disabled** (`SSL_VERIFY_NONE`) to accept the
  self-signed certificate a default SQL Server presents. Do not use this against
  a server you don't control without adding proper verification.
- **Encryption is negotiated, not assumed.** The client requests `ENCRYPT_OFF`
  in pre-login and then reads the server's `ENCRYPTION` response. If the server
  chose `ENCRYPT_ON`/`ENCRYPT_REQ`, the whole session is TLS: the login response
  and every query travel through `SSL_write`/`SSL_read`. If it chose
  `ENCRYPT_OFF`, only the login is encrypted and query traffic is plaintext TDS.
  The negotiated mode is printed at startup (`session encryption: ON/OFF`).
  After the TLS handshake, TLS records are sent raw (the TDS packets become the
  plaintext *inside* them); during the handshake they are wrapped inside `0x12`
  TDS packets.
- **MARS is deliberately disabled.** The pre-login requests `MARS = 0`. With
  MARS enabled the server expects every post-login packet to be wrapped in an
  SMP (Session Multiplexing Protocol) header, which this client does not
  implement — negotiating MARS on makes SQL Server accept the login but then
  drop the connection on the first SQL batch.
- **Query responses are fully reassembled** across TDS packets and `recv`
  boundaries (via `tds_read_message`); the pre-login/handshake path still assumes
  one packet per `recv`.
- **Output is UTF-8.** The console output code page is switched to UTF-8, so
  Turkish (and other) characters render correctly. `n(var)char`/`ntext` is
  decoded from UTF-16LE; legacy single-byte `(var)char`/`text` is decoded via
  the system ANSI code page (Windows-1254 on a Turkish system) — best-effort
  when the column's collation differs from the system default. The SQL text you
  type is assumed ASCII.
- **Tables adapt to the terminal.** Column widths are measured in display
  columns (UTF-8 aware); over-long cells are truncated with an ellipsis (`…`)
  and numeric columns are right-justified. When a grid would be wider than the
  terminal, output switches to an **expanded** (one field per line) layout —
  toggle it manually with `\x`. Rows are buffered before rendering (capped at
  100,000 per result set).

## What's next

- Multi-line statement buffering (a `GO`-style terminator).
- Session encryption support (`ENCRYPT_ON`) for the query path.
- Deriving the exact varchar code page from the column collation.

## Why

SSMS round-trips get tiring. The longer-term aim is a `psql`-style terminal
client for SQL Server. This client is the protocol foundation for that.

## Reference

- **[MS-TDS]: Tabular Data Stream Protocol** — Microsoft's official wire-format spec.
- **Beej's Guide to Network Programming** — for the socket layer.
- OpenSSL `SSL_do_handshake` / memory BIO documentation — for driving TLS by hand.