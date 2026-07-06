# tdsh

**A `psql`-style terminal client for Microsoft SQL Server — the TDS wire protocol,
hand-written in C.**

No FreeTDS, no ODBC, no database driver of any kind. Just Winsock, OpenSSL, and
the [MS-TDS] specification: `tdsh` opens a raw socket, negotiates TLS *inside* TDS
packets, builds a `LOGIN7` packet byte by byte, authenticates, and then runs T-SQL
from an interactive prompt — rendering result sets as coloured, terminal-fitting
tables.

It is a learning project. The goal was to understand the protocol down to the
byte, not to ship a production driver — but it works against a real SQL Server.

```text
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
```

---

## Highlights

- **Speaks TDS from scratch** — pre-login, TLS-over-TDS handshake, dynamically
  built `LOGIN7`, and full result-token parsing. No driver in sight.
- **Interactive REPL** with multi-line `GO` batching and a small line editor
  (command history, arrow-key cursor editing).
- **Readable output** — coloured box tables that shrink to the terminal, an
  automatic expanded layout for very wide rows, and a screenful pager.
- **psql-flavoured meta-commands** — `\dt`, `\d <table>`, `\l`, `\timing`,
  `\o` CSV/TSV export, and more.
- **Encryption-aware** — negotiates the server's encryption mode and drives
  OpenSSL by hand through memory BIOs.
- **Broad type coverage** — every TDS length encoding (incl. PLP/`MAX` and
  text-pointer), and formatting for numbers, decimals, the full date/time family,
  `uniqueidentifier`, strings, and binary.

---

## Build

Requires a C compiler, OpenSSL, and (on Windows) Winsock. Developed with **MSYS2
UCRT64** on Windows 11.

```sh
gcc -Wall *.c -o tdsh.exe -lws2_32 -lssl -lcrypto
```

The sources are split into modules that share a single header (`tdsh.h`), so
`*.c` compiles the whole client. On Linux the socket layer would swap Winsock for
POSIX sockets (the `#ifdef`-guarded part); the TDS and TLS logic is portable.

> **Tip:** on Windows the link step fails if a `tdsh.exe` is still running (the
> file is locked). Close it first.

---

## Usage

Two ways to connect:

```sh
# 1) interactive — fill in a connection form (host, port, user, password, db)
./tdsh.exe

# 2) scripting — pass everything on the command line
./tdsh.exe <host> <port> <username> <password> <database>
./tdsh.exe 192.168.1.50 1433 sa MyPassword master
```

The interactive form offers sensible defaults (`localhost`, `1433`, `sa`,
`master`) and masks the password as you type.

After `Login Success` you land in the prompt. Type T-SQL across as many lines as
you like and enter **`GO`** on its own line to run the batch. Everything `tdsh`
handles itself starts with a backslash; `\help` lists those. Leave with `\exit`
(or `\q`, or EOF — `Ctrl+Z` then Enter on Windows).

### The prompt

Statements accumulate until a standalone `GO`, so multi-line queries read
naturally — `;` stays a *statement separator inside* the batch, exactly as in SQL
Server tooling. A continuation prompt (`  ...>`) shows while a batch is open.

The prompt has a small **line editor**:

| Key | Action |
|---|---|
| ↑ / ↓ | recall previous / next line from history |
| ← / → | move the cursor |
| Home / End | jump to start / end of the line |
| Backspace / Delete | edit in place |
| Ctrl+C | cancel the current line |
| Ctrl+Z, Enter | end the session (EOF) |

When input is redirected (piping a script in), the editor falls back to plain
line reads, so `GO`-separated scripts still run unattended.

### Meta-commands

| Command | Action |
|---|---|
| `\help`, `\?` | show the command list |
| `\l` | list databases (`sys.databases`) |
| `\dt` | list tables |
| `\dv` | list views |
| `\dn` | list schemas |
| `\d <table>` | describe a table's columns |
| `\timing` | toggle per-batch elapsed time |
| `\o <file>` | write result sets to a CSV/TSV file (`\o` alone: back to the screen) |
| `\x` | toggle expanded (one-field-per-line) display |
| `\pager` | toggle screen-at-a-time paging |
| `\clear`, `\cls` | clear the screen |
| `\exit`, `\q` | leave tdsh |

The catalog commands are thin wrappers that run canned `sys.*` queries and render
them like any other result. `\o` picks its delimiter from the file extension
(`.tsv` → tab, otherwise comma) and quotes fields per RFC 4180.

---

## Output & rendering

Results come back as a coloured box table. Column widths are measured in **display
columns** (UTF-8 aware), numeric columns are right-justified, and over-long cells
are truncated with an ellipsis (`…`).

When a grid would be wider than the terminal, output switches automatically to an
**expanded** layout — one `column │ value` line per field, grouped per record,
like psql's `\x`:

```text
tdsh> SELECT * FROM ETKINLIK
  ...> GO
[ RECORD 1 ]──┼────────────────────────
id            │ 1
ad            │ Bahar Konseri
tarih         │ 2024-04-20
...
```

Toggle it manually with `\x`. Long result sets are **paged** a screenful at a
time (Enter/Space for the next page, `q` to stop) so nothing scrolls off unseen.

---

## How it works

`main` drives the connection through five stages:

1. **TCP connect** to the server.
2. **Pre-login** — send the option table, read the server's `ENCRYPTION`
   response, and decide whether the whole session will be encrypted.
3. **TLS handshake wrapped inside TDS** — the unusual part of TDS: each TLS
   handshake message is carried as the payload of a `0x12` TDS packet. OpenSSL is
   driven manually through memory BIOs rather than owning the socket.
4. **`LOGIN7`** — a fixed header, a dynamically computed offset/length table,
   UTF-16LE field data, and the password obfuscated with the TDS nibble-swap +
   XOR `0xA5` scheme, sent over the encrypted channel.
5. **REPL** — each `GO`-terminated batch is sent as a SQL batch (`0x01`) packet,
   the response is reassembled across TDS packets, its result token stream is
   parsed (`COLMETADATA` → `ROW`/`NBCROW` → `DONE`), and rows are rendered.

### Project layout

The code is split into modules that share one header (`tdsh.h` — protocol
constants, the `Column`/`Table` types, the global session flags, and the
cross-module prototypes):

| Module | Responsibility |
|---|---|
| `tds.c` | TCP connect; pre-login; TLS-in-TDS handshake; `LOGIN7`; TDS packet framing and reassembly; low-level little-endian and socket I/O |
| `format.c` | `TYPE_INFO` decode, row-value reading, value → text formatting, UTF-16/ANSI → UTF-8 |
| `render.c` | display-width math, coloured box tables, expanded layout, pager, CSV/TSV export, and the result token-stream walk |
| `repl.c` | batch execution, `GO` buffering, meta-commands, the line editor + history, and the connection form |
| `main.c` | orchestration (connect → pre-login → TLS → login → REPL) and the global definitions |

### Result-set support

The result token-stream walker handles:

- **Tokens:** `COLMETADATA` (`0x81`), `ROW` (`0xD1`), `NBCROW` (`0xD2`, null-bitmap
  compressed rows), `DONE`/`DONEPROC`/`DONEINPROC`, `RETURNSTATUS`, and the
  variable-length `ERROR`/`INFO`/`ENVCHANGE`/`ORDER`/… tokens.
- **All row length encodings:** fixed-length, byte-length, `USHORT`-length,
  `LONG`-length (text/ntext/image via text pointer), and **PLP** for the `MAX`
  types.
- **Value formatting:** integers, `bit`, `real`/`float`, `money`,
  `decimal`/`numeric` (arbitrary precision via base-10 conversion),
  `date`/`datetime`/`smalldatetime`/`datetime2`/`time`/`datetimeoffset`,
  `uniqueidentifier`, `(n)char`/`(n)varchar`/text, and `binary`/`varbinary` as
  hex. `NULL` shows as `NULL`. Unknown types stop the parse rather than misalign
  the stream.

---

## Notes & limitations

Intentionally minimal and lab-oriented:

- **Certificate verification is disabled** (`SSL_VERIFY_NONE`) to accept the
  self-signed certificate a default SQL Server presents. Do not point this at a
  server you don't control without adding real verification.
- **Encryption is negotiated, not assumed.** Pre-login requests `ENCRYPT_OFF` and
  reads back the server's choice. Under `ENCRYPT_ON`/`REQ` the whole session is
  TLS (login response *and* every query go through `SSL_write`/`SSL_read`); under
  `ENCRYPT_OFF` only the login is encrypted and query traffic is plaintext TDS.
  The negotiated mode is printed at startup. After the handshake, TLS records are
  sent raw with the TDS packets as their plaintext payload; *during* the
  handshake those records are wrapped inside `0x12` TDS packets.
- **MARS is deliberately off.** Pre-login requests `MARS = 0`; with MARS on, the
  server expects every post-login packet wrapped in an SMP header this client
  doesn't implement (it would accept the login, then drop the first batch).
- **Query responses are fully reassembled** across TDS packets and `recv`
  boundaries; the pre-login/handshake path still assumes one packet per `recv`.
- **Output is UTF-8.** The console output code page is switched to UTF-8;
  `n(var)char`/`ntext` decodes from UTF-16LE and legacy `(var)char`/`text` via the
  system ANSI code page (best-effort when the column collation differs). SQL text
  you type is converted UTF-8 → UTF-16LE before sending, so non-ASCII literals
  survive the round trip.
- **Rows are buffered before rendering**, capped at 100,000 per result set.

---

## Roadmap

Shipped recently: modular source layout, multi-line `GO` batching, a history +
arrow-key line editor, the `\l`/`\dt`/`\d`/`\dn`/`\dv` catalog commands,
`\timing`, and `\o` CSV/TSV export.

Still ahead:

- **Wide-glyph width** (a `wcwidth`-style table) so CJK/double-width characters
  don't skew table alignment.
- **Exact varchar code page** derived from the column collation instead of the
  system ANSI default.
- **Streaming render** for very large result sets, beyond the 100,000-row buffer.
- **Informational tokens** (`INFO` `0xAB` — `PRINT` output, rows-affected messages).
- **POSIX/Linux port** (Winsock → BSD sockets, `_getch` → termios).
- **Integrated Windows auth** (SSPI/NTLM) alongside SQL login.
- **Connection resilience** (keep-alive, timeouts, reconnect on a dropped link).

---

## Reference

- **[MS-TDS]: Tabular Data Stream Protocol** — Microsoft's official wire-format spec.
- **Beej's Guide to Network Programming** — for the socket layer.
- OpenSSL `SSL_do_handshake` / memory-BIO documentation — for driving TLS by hand.

[MS-TDS]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/
