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
6. Drops into an **interactive REPL** with a small line editor (command history,
   arrow-key cursor editing): you type T-SQL across as many lines as you like and
   a standalone **`GO`** sends the buffered **SQL batch** (`0x01` packet). The
   response is reassembled across TDS packets, its **result token stream** is
   parsed (`COLMETADATA` → `ROW`/`NBCROW` → `DONE`), and rows are printed as an
   **aligned table** (or exported to CSV/TSV).

## Build

Requires a C compiler, OpenSSL, and (on Windows) Winsock. Developed with MSYS2
UCRT64 on Windows.

```
gcc -Wall *.c -o tdsh.exe -lws2_32 -lssl -lcrypto
```

The sources are split into modules (`tds.c`, `format.c`, `render.c`, `repl.c`,
`main.c`) sharing one header (`tdsh.h`), so `*.c` compiles the whole client.

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

After `Login Success` you land in the interactive prompt. Type T-SQL over one or
more lines and enter **`GO`** on its own line to run the batch; the result comes
back as a coloured box table. `\exit` (or `\q`, or EOF — `Ctrl+Z` then Enter on
Windows) leaves the loop. Every command tdsh handles itself starts with a
backslash; `\help` lists them.

```
Login Success

  tdsh interactive — type T-SQL, GO to run, \help for commands.

tdsh> SELECT name, database_id
  ...> FROM sys.databases
  ...> GO
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

Statements accumulate until a standalone `GO`, so multi-line queries read
naturally (`;` stays a statement separator *inside* the batch, as in SQL Server).
The prompt has a small **line editor**: ↑/↓ recall previous lines, ←/→/Home/End
move the cursor, and Backspace/Delete edit in place. When input is redirected
(scripting) it falls back to plain line reads, so piped `GO`-separated scripts
still work.

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

Meta-commands (all start with `\`):

| Command | Action |
|---|---|
| `\help`, `\?` | show the command list |
| `\l` | list databases (`sys.databases`) |
| `\dt` | list tables |
| `\dv` | list views |
| `\dn` | list schemas |
| `\d <table>` | describe a table's columns |
| `\timing` | toggle per-batch elapsed time |
| `\o <file>` | write result sets to a CSV/TSV file (`\o` alone returns to the screen) |
| `\x` | toggle expanded display (off = auto) |
| `\pager` | toggle paging |
| `\clear`, `\cls` | clear the screen |
| `\exit`, `\q` | leave tdsh |

The catalog commands (`\l`, `\dt`, `\d`, …) are thin wrappers that run canned
`sys.*` queries and render them like any other result. `\o` picks the delimiter
from the file extension (`.tsv` → tab, otherwise comma) and quotes fields per
RFC 4180.

## How it is structured

The code is split into modules that share one header (`tdsh.h`, holding the
protocol constants, the `Column`/`Table` types, the global session flags, and the
cross-module prototypes):

| Module | Responsibility |
|---|---|
| `tds.c` | TCP connect; pre-login; TLS-in-TDS handshake; `LOGIN7`; TDS packet framing/reassembly (`tds_send_message`/`tds_read_message`); low-level LE + socket I/O |
| `format.c` | `TYPE_INFO` decode (`parse_type_info`), row-value reading (`read_cell`) and text formatting (`format_cell`), UTF-16/ANSI → UTF-8 |
| `render.c` | display-width math, coloured box tables, expanded layout, screenful pager, CSV/TSV export, and the result token-stream walk (`parse_result_stream`) |
| `repl.c` | batch execution (`tds_exec`), `GO` buffering, meta-commands, the line editor + history, the REPL, and the connection form |
| `main.c` | orchestration (connect → pre-login → TLS → login → REPL) and the global definitions |

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
  type is converted from UTF-8 to UTF-16LE before it is sent, so non-ASCII
  literals survive the round trip.
- **Tables adapt to the terminal.** Column widths are measured in display
  columns (UTF-8 aware); over-long cells are truncated with an ellipsis (`…`)
  and numeric columns are right-justified. When a grid would be wider than the
  terminal, output switches to an **expanded** (one field per line) layout —
  toggle it manually with `\x`. Rows are buffered before rendering (capped at
  100,000 per result set).

## What's next

Done recently: modular source layout, multi-line `GO` batching, a history +
arrow-key line editor, `\l`/`\dt`/`\d`/`\dn`/`\dv` catalog commands, `\timing`,
and `\o` CSV/TSV export.

Still on the roadmap:

- **Wide-glyph width** (a `wcwidth`-style table) so CJK/double-width characters
  don't skew table alignment.
- **Deriving the exact varchar code page** from the column collation instead of
  the system ANSI default.
- **Streaming render** for very large result sets instead of buffering to the
  100,000-row cap.
- **Informational tokens** (`INFO` 0xAB — `PRINT` output, rows-affected messages).
- **POSIX/Linux port** (Winsock → BSD sockets, `_getch` → termios).
- **Integrated Windows auth** (SSPI/NTLM) alongside SQL login.
- **Connection resilience** (keep-alive, timeouts, reconnect on a dropped link).

## Why

SSMS round-trips get tiring. The longer-term aim is a `psql`-style terminal
client for SQL Server. This client is the protocol foundation for that.

## Reference

- **[MS-TDS]: Tabular Data Stream Protocol** — Microsoft's official wire-format spec.
- **Beej's Guide to Network Programming** — for the socket layer.
- OpenSSL `SSL_do_handshake` / memory BIO documentation — for driving TLS by hand.