
| Supported Targets | ESP32 | ESP32-C3 | ESP32-S2 | ESP32-S3 |
| ----------------- | ----- | -------- | -------- | -------- |

# ESP-Crash Example (`esp-crash-example`)

This example is tied to esp-crash, which can be found at https://esp-crash.wennlund.nu/. It is a free service to monitor and display crashes.

## For Newcomers

If this is your first time here, the repository is organised into three main pieces:

- **Component Library** – the files in the root directory (`esp_crash.c`, `esp_crash_cli.c`, etc.) implement crash handling and upload helpers that you can add to any ESP‑IDF project.
- **Example Application** – `examples/esp-crash-example` shows how to use the component in a simple project. Building this example is a good way to test that everything works on your board.
- **Server** – `esp-crash-server` contains a small Flask application for receiving and displaying uploaded crashes. You can run it yourself or use the hosted service linked above.

To explore the project quickly, build and flash the example, trigger a crash with `coredump_crash`, and upload it using `coredump_upload`. Inspect the server code or the hosted instance to see your crash reports.


## Using the component

Run the following command in your ESP-IDF project to install this component:
```bash
idf.py add-dependency "jimmyw/esp-crash"
```

## Example

To run the provided example, create it as follows:

```bash
idf.py create-project-from-example "jimmyw/esp-crash:esp-crash-example"
```

Then build as usual:
```bash
cd esp-crash-example
idf.py build
```

And flash it to the board:
```bash
idf.py -p PORT flash monitor

coredump_crash

coredump_upload
```

## License

This component is provided under Apache 2.0 license, see [LICENSE.txt](LICENSE.txt) file for details.

## Contributing

Please check the repository for contribution guidelines.


## How to use esp-crash

This example uses a coredump partition, named coredump. The built-in crash-handler will write a crash to this partition if you enable CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH=y in your sdkconfig.

To add a coredump partition to your esp-idf partition.csv file, you can use the following example:

```
# Name,   Type, SubType, Offset,  Size, Flags
nvs,      data, nvs,     0x9000,  0x5000,
phy_init, data, phy,     0xe000,  0x2000,
factory,  app,  factory, 0x10000, 1M,
coredump, data, coredump, ,       128K,
```
This will create a 64K coredump partition. If you have a lot of tasks, you need to increase the size to fit all data.

Before you can see your uploaded crashes, you need to access https://esp-crash.wennlund.nu/ with your GitHub account, and register a new unique PROJECT_NAME. After you have registered it, you can add additional team members who can also examine the crashes.

## Tags

Crashes can be tagged (e.g. `reviewed`, `wontfix`, `duplicate`, or anything
else) from the crash detail page. Pick an existing tag from the dropdown or
type a new name to create it for that project - each tag can carry a
description, shown on hover. Tags appear as badges in both the crash list
and crash detail page; clicking one filters the crash list down to just that
tag.

## MCP Server (AI tool access)

Besides the web UI, your crash data is also reachable by AI tools (Claude,
other MCP-compatible clients) through an MCP server at
`https://mcp-esp-crash.wennlund.nu/mcp`. It speaks Streamable HTTP and uses
the same GitHub login as the web app — you only see/modify the projects your
GitHub account already has access to via `https://esp-crash.wennlund.nu/`.

Available tools: `list_projects`, `list_crashes`, `get_crash`, `list_builds`,
`get_build`, `list_tags`, `refresh_crash`, `delete_crash`, `delete_build`,
`create_project`, `add_tag_to_crash`, `remove_tag_from_crash`.

### Adding it to Claude Code

```bash
claude mcp add --transport http esp-crash https://mcp-esp-crash.wennlund.nu/mcp
claude mcp login esp-crash
```

The login command prints a GitHub authorization URL; open it, sign in, and
approve. Run it in a real interactive terminal — completing the redirect
needs a local browser/terminal round trip.

### Adding it to other MCP clients

Any client that supports Streamable HTTP + OAuth (e.g. Claude Desktop, MCP
Inspector) just needs the server URL:

```
https://mcp-esp-crash.wennlund.nu/mcp
```

The client will discover the OAuth endpoints automatically and prompt you to
log in with GitHub on first use.

## ESP-Crash Identifier

Using
```
esp_err_t esp_crash_identifier_setup()
```
you can add an identifier to RAM, which will always be included in your crash dump. This identifier is in the format:

Go to https://esp-crash.wennlund.nu/ and register a unique PROJECT_NAME that only you have access to. You can pick anything that is free.

```
ESP_CRASH:<PROJECT_NAME>;<PROJECT_VER>;<DEVICE_ID>;
```
Example:
```
ESP_CRASH:esp-crash-example;8e8e8df-5.1;6941729232066;
```
This is critical for our backend to pick up, just make it available to your registered project, and know what build file to match up.

## Uploading coredumps

Use
```
esp_err_t upload_coredump(const char *url, const char *filename)
```
to upload the coredump directly from a partition to a server. This will read the flash partition and send it as raw data. Upload your crashes to "https://esp-crash.wennlund.nu/dump" if you like to have a free store for your crashes.

## Downloading coredumps

Use
```
esp_err_t esp_crash_webserver_start(httpd_handle_t handle)
```
to register the /crash.dmp webserver endpoint. Curling this address will download the last crash if available. After downloading this crash, you can upload it again to "https://esp-crash.wennlund.nu/dump" if you like.

```
curl "https://esp-crash.wennlund.nu/dump" -F file=@crash.dmp

OR compressed

bzip2 -c crash.dmp | curl "https://esp-crash.wennlund.nu/dump" -F file=@-

```


## Interval crash upload

Use
```
esp_err_t esp_crash_upload_timer_init()
```
to enable a 60s interval timer, that will try to find an existing core dump, and upload if possible. On success, the coredump partition will be erased.

## Uploading build files

To be able to examine your crashes, you also need to upload the elf binary, with debugging symbols. This can be done with this one-liner:

```
curl "https://esp-crash.wennlund.nu/upload_elf?project_name=esp-crash-example&project_ver=$VERSION" -F file=@build/esp-crash-example.elf

OR

bzip2 -c build/esp-crash-example.elf | curl "https://esp-crash.wennlund.nu/upload_elf?project_name=esp-crash-example&project_ver=$VERSION" -F file=@-

```

Ensure $VERSION matches the same PROJECT_VER in your build. This command can easily be added to your CI system.

### CLI commands
```
coredump_crash
  Crash the esp32

coredump_erase
  Erase coredump partition

coredump_upload  [-e] [url] [filename]
  Upload core dump to server
           url  Url to send to
      filename  Filename
   -e, --erase  Erase after successful upload
```

## Dynamically loaded ELF modules

If your firmware loads ELF modules at runtime (for example with an ELF loader /
mod loader), those modules are not part of your main application ELF, so the
backend can't symbolicate their stack frames — crashes inside a module show up
as raw addresses.

The device records a small **module registry** in a `COREDUMP_DRAM_ATTR`
variable, so it is captured inside every coredump. Each record holds the
module's name, its version string, the SHA1 of the over-the-wire `.app` bytes,
and its section runtime addresses. There are two ways to use it:

- **Server-side (automatic):** pre-upload each module's debug ELF, keyed by the
  SHA1 of its `.app` bytes. When a dump arrives, the backend reads the registry,
  matches each module by SHA1, and symbolicates automatically.
- **Local:** run `esp-crash-server/decode_module_coredump.py` against a dump you
  downloaded, supplying each module ELF by name. The script runs `esp-coredump`
  with a checked-in gdb macro that reads the registry symbolically (by the
  `s_mod_map` symbol) and issues an `add-symbol-file` per module, each section
  placed at its on-device runtime address as evaluated by gdb against the dump.

### Uploading module ELFs

So the backend can symbolicate module frames, upload each module's **debug** ELF
keyed by the SHA1 of its over-the-wire `.app` bytes — the same SHA1 the device
stores in the registry. This is what lets the server match an uploaded ELF to a
module seen in a dump.

```bash
SHA1=$(sha1sum your-module.app | awk '{print $1}')

curl -F file=@your-module.debug.elf \
  "https://esp-crash.wennlund.nu/upload_module_elf?name=your-module&app_sha1=$SHA1"

OR compressed

SHA1=$(sha1sum your-module.app | awk '{print $1}')
bzip2 -c your-module.debug.elf | curl -F file=@- \
  "https://esp-crash.wennlund.nu/upload_module_elf?name=your-module&app_sha1=$SHA1"
```

Hash the `.app` bytes the device actually receives (the signed payload), but
upload the unstripped `.debug.elf` so symbols are available. `app_sha1` must be
40 hex characters. Like the build-file upload, this fits neatly into CI.

### Decoding locally with the script

This runs on a developer host, not in the server image — that image ships no
debugger and no `esp-coredump`, since decoding happens inside the sandboxed
debug service. Keep it for reproducing a decode by hand, and as the reference
to diff against when a sandboxed report looks wrong. It needs IDF,
`esp-coredump` and a per-chip gdb on `PATH`.

```bash
python esp-crash-server/decode_module_coredump.py info \
    --core crash.dmp \
    --prog build/your-app.elf \
    --module-elf ems-goodwe=modules/ems-goodwe/build/ems-goodwe.app.elf
```

- `info` prints a symbolicated backtrace; `dbg` drops you into an interactive
  GDB session.
- `--module-elf name=path` is repeatable — supply one per loaded module. The
  `name` must match the name the module was registered under on-device.
- Module names found in the dump with no matching `--module-elf` are skipped
  with a warning; the rest of the dump still decodes.

### On-device registry contract

The decoder reads the module registry **symbolically** — it never scans the dump
for a magic tag. Your firmware must expose a symbol named `s_mod_map` that is:

- an **array of module records** (`mod_record_t s_mod_map[N]`), where `N` is your
  concurrent-module cap;
- placed in `COREDUMP_DRAM_ATTR` storage so it lands in every coredump;
- present in the **program ELF with DWARF type info** (an unstripped, `-g` build —
  the default). gdb reads the slot count from the array type and each field from
  the dump, so there is no host-side knowledge of the byte layout.

Each record must contain these fields (names matter — the gdb scripts reference
them by name):

```
record  { char name[]; char version[]; uint8_t sha1[20];
          section text; section data; section bss; section rodata; }
section { uint32_t addr; uint32_t v_addr; uint32_t size; }
```

`addr` is the **runtime** address of the section (what gdb's `add-symbol-file`
needs), `v_addr` is the ELF link-time virtual address, `size` is the section size.
A slot is occupied iff `name[0] != 0` **and** `text.addr != 0`; zeroed slots (free)
and slots with a name but `text.addr == 0` (mid-load) are skipped.

### C example

```c
#include "esp_attr.h"   // COREDUMP_DRAM_ATTR
#include <stdint.h>

#define MOD_MAP_MAX_MODULES  4   // your concurrent-module cap

typedef struct {
    uint32_t addr;    // runtime address (passed to add-symbol-file via gdb)
    uint32_t v_addr;  // ELF link-time virtual address
    uint32_t size;
} mod_map_section_t;

typedef struct {
    char    name[32];     // NUL-terminated module name
    char    version[24];  // NUL-terminated version string (informational)
    uint8_t sha1[20];
    mod_map_section_t text, data, bss, rodata;
} mod_record_t;

// No magic, no capacity header: the decoder locates this by the `s_mod_map`
// symbol and reads N from the DWARF array type.
COREDUMP_DRAM_ATTR static mod_record_t s_mod_map[MOD_MAP_MAX_MODULES];
```

The `sha1` field is the SHA1 of the over-the-wire `.app` bytes and is the join key
for **server-side** symbolication: the backend matches it against the `app_sha1`
used when uploading the module ELF. The **local** CLI matches by name instead
(it has the debug `.elf`, not the wire `.app`), so there `sha1` is informational.

The `version` field is a free-form module version string (e.g.
`"1560-a6f50c32-dirty"`). It is informational — not used for matching — and is
surfaced on the crash page's module card alongside the name and SHA1. Field
sizes are up to your firmware; the decoder reads each field symbolically by name
from DWARF, so only the field **names** (`name`, `version`, `sha1`, the section
members) must match.

## Example Output



## Interactive in-browser gdb sessions

A crash page shows a **Debug** link when the project has a debug toolchain
configured. It opens a real gdb console in the browser: `bt`, `info locals`,
`p *handle`, `frame 3` — the full command set, on the actual core, with your
build's symbols and any runtime module symbols already loaded. No download, no
local toolchain.

Each session runs in its own bubblewrap sandbox for as long as the WebSocket is
open, and is destroyed when you close the page.

### Enabling it

1. **Build a toolchain package** and mount it read-only at `/opt/toolchains` on
   `backend`, `backend-dev` and `esp-crash-gdb` — see
   [Toolchain packages](#toolchain-packages). Without one there are no
   toolchains, so no sessions and no batch decoding.
2. Set `GDB_TICKET_SECRET` and `GDB_PUBLIC_WS_URL` on the `backend` service, and
   the *same* `GDB_TICKET_SECRET` on the `esp-crash-gdb` service (see
   `docker-compose.yml.template`). With either unset, no Debug link appears.
3. Set a shared `DECODE_SERVICE_TOKEN` on `cron` and `esp-crash-gdb`, plus
   `DECODE_SERVICE_URL` on `cron`, or cron cannot decode at all — the web and
   cron images carry no debugger.
4. Point your reverse proxy at the `esp-crash-gdb` container's port 8002, with
   WebSocket upgrade allowed and `timeout tunnel` set.
5. In **project settings → Debug toolchain**, pick a toolchain. There is
   deliberately no default *per project*: loading a build into a debugger for
   the wrong architecture produces confident nonsense rather than an error. A
   project with none set offers no interactive session and falls back to
   `GDB_DEFAULT_TOOLCHAIN` for batch decoding.

`GET /v1/info` on the service lists the toolchains it found, how many slots each
pool has free, and whether the decode endpoint is enabled — the quickest way to
tell whether the mount actually arrived.

### How the sandbox works

Everything gdb needs is already in Postgres, so a session is materialised
straight from the stored blobs into a private work directory — there is no
bundle and nothing is written outside a tmpfs.

Two jails, because parsing an untrusted crash artifact and holding an
interactive console are very different risks:

- **Conversion** — short-lived and timeout-bounded, this is where the raw
  device-supplied dump is parsed (via `esp-coredump` for ESP targets). It is
  allowed to carry a Python runtime because it exits immediately.
- **Session** — holds the pty, but runs *plain gdb only* on the already-converted
  core plus literal `add-symbol-file` lines. No interpreter, no shell: gdb's
  `shell` and `python` commands fail for want of a binary rather than because a
  blocklist rejected them.

Each jail is an empty tmpfs root, remounted read-only, with only an explicitly
enumerated set of read-only binds on top: the toolchain package, the `ldd`
closure of every executable it names, and whatever else its descriptor asks
for. The closure is computed when the toolchain is loaded rather than recorded
when it was built, because it belongs to the *runtime* image — a package built
on Arch resolves `/usr/lib/libc.so.6` where the Debian-based server image needs
`/lib/x86_64-linux-gnu/libc.so.6`. The jail has no network and no `/proc`, and
the only writable path is its own work directory.

Sessions cannot reach each other. Every live session gets a dedicated uid from a
pool of accounts baked into the image, so a cross-session `ptrace` or `kill` is
a kernel-level `EPERM`, and `RLIMIT_NPROC` — enforced per uid — bounds each
session's processes independently. Separate user, pid, net, ipc, uts and cgroup
namespaces mean one session cannot even enumerate another's processes, and the
directory holding session work dirs does not exist inside a jail, so peers
cannot be named. The database credentials stay in the service process; the
debugger never has database access or a network.

Interactive sessions and batch decoding draw from **disjoint** identity pools —
28 and 4 of the 32 accounts by default. Partitioning rather than sharing is what
guarantees a decode backlog cannot take the last slot an interactive user is
waiting for.

Access is checked twice: the web app authorises the request against the same
`project_auth` ACLs as everything else and issues a 60-second single-use ticket,
and the debug service independently re-checks that access against the database
before starting anything — so a leaked signing key alone grants nothing, and an
ACL revoked a second ago takes effect immediately.

Sessions end on disconnect, after 30 minutes idle, or after 4 hours total,
whichever comes first; the process group is killed and the work directory
removed. The idle clock only advances on input from the browser, and reading a
backtrace while thinking is the most common thing anyone does in a debugger, so
those limits are deliberately generous — they exist to reclaim crashed browsers
and dropped networks, not to hurry anyone along.

If you put the service behind HAProxy, set **`timeout tunnel`** on its backend.
Once a WebSocket is upgraded that is the timeout which governs it, falling back
to `timeout server` when unset — and a short server timeout drops an idle
session mid-use.

### Batch decoding runs in the same sandbox

The pre-analysis that fills in `crash.dump` used to shell out to `esp-coredump`
and gdb inside the cron process. It now calls `POST /v1/decode` on the debug
service, so the parsing of device-supplied bytes is sandboxed on the batch path
too, not just the interactive one — and the web and cron images need no debugger
at all.

That endpoint performs an **unscoped** read (any crash, any project), because
cron processes every project. It is therefore gated on its own
`DECODE_SERVICE_TOKEN`, is reachable only on the internal network, is *not*
served under `GDB_PATH_PREFIX` so the reverse proxy cannot expose it, and is not
registered at all when that token is unset.

`GDB_DEFAULT_TOOLCHAIN` is used for projects that have not chosen one. Without
it, crashes in unconfigured projects would simply stop being decoded.

## Toolchain packages

A toolchain is a **package**: a self-contained directory holding a debugger,
whatever data files it needs, optionally its own interpreter, and a
`toolchain.yml` describing how to drive it. Packages are built outside the image
and bind-mounted read-only, so adding support for a chip family is dropping in a
directory — no rebuild, no redeploy.

```sh
# build one (downloads and verifies everything, ~112 MB for Espressif)
./esp-crash-server/toolchains/recipes/xtensa-esp.sh --out /opt/esp-crash-toolchains

# or produce a versioned tarball to copy to another machine
./esp-crash-server/toolchains/recipes/xtensa-esp.sh --out ./dist --tarball
```

Then mount it read-only at `/opt/toolchains` on `backend`, `backend-dev` and
`esp-crash-gdb` (see `docker-compose.yml.template`). The web app reads the
descriptors for the settings dropdown and to decide whether to offer the Debug
link; the debug service reads them to run sessions.

### The descriptor

The format is deliberately not gdb- or Espressif-shaped. The service needs
exactly four things from a toolchain — a file the debugger can open, report
text, an interactive command, and optionally a way to enumerate and symbolise
runtime-loaded modules — so those are the named phases, and everything else is
the vendor's business:

```yaml
schema: 1
name: xtensa-esp
arch: xtensa
version: "16.3_20250913"

debugger: gdb/bin/xtensa-esp-elf-gdb-no-python
python: python/bin/python3          # optional; referenced as {python}

env:
  ESP_ROM_ELF_DIR: "{root}/rom-elfs/"
binds: [/usr/lib/locale, /lib/terminfo, /usr/share/terminfo]
requires: [prog]

core:                               # raw artifact -> a file the debugger opens
  commands:
    - ["{python}", -m, esp_coredump, info_corefile, -t, raw,
       -c, "{dump}", --save-core, "{core}", --gdb, "{debugger}", "{prog}"]

report:                             # the text stored as crash.dump
  with_symbols: [--extra-gdbinit-file, "{symbols_file}"]
  commands: [[...]]

interactive:                        # what the pty attaches to
  command: ["{debugger}", -nx, -q, "{prog}", -ex, "core-file {core}"]

modules:                            # omit entirely if the target has none
  registry: esp_crash_modmap
  batch: ["{debugger}", -batch, -nx, "{prog}", -ex, "core-file {core}"]
  add_symbols:
    - "add-symbol-file {elf} {text:#x} -s .data {data:#x} ..."

variants:                           # one payload, several selectable ids
  xtensa-esp32:   { chip: esp32,   env: { XTENSA_GNU_CONFIG: "{root}/gdb/lib/xtensa_esp32.so" } }
  xtensa-esp32s2: { chip: esp32s2, env: { XTENSA_GNU_CONFIG: "{root}/gdb/lib/xtensa_esp32s2.so" } }
```

Placeholders are a closed set (`{root} {debugger} {python} {dump} {prog} {core}
{symbols_file} {work}`, plus the module fields inside `add_symbols`), and an
unrecognised one is a load error rather than a literal that fails somewhere far
away. Commands are argv lists substituted per element and executed without a
shell, so no descriptor value can inject an argument.

`variants` exists because the three Xtensa chips differ only in a ~400 KB core
configuration object. Per-chip packages would triplicate a 9 MB debugger and an
86 MB interpreter for that.

**The toolchains directory is as trusted as the image was** — a descriptor names
commands to execute. Mount it read-only, own it as root, and never let the
`gdbrun*` accounts write to it.

### Adding another architecture

Most of the work is *omission*. A target whose crash artifact is already an ELF
core needs no `core` phase; one with no runtime module registry needs no
`modules` section; one whose report comes from the debugger itself needs no
interpreter. That is the whole ARM descriptor:

```yaml
schema: 1
name: arm-none-eabi
arch: arm
version: "10.2_2020q4"
debugger: bin/arm-none-eabi-gdb
binds: [/usr/lib/locale, /lib/terminfo]
requires: [prog]

report:
  commands:
    - ["{debugger}", -batch, -nx, "{prog}", -ex, "core-file {core}",
       -ex, "thread apply all bt full"]

interactive:
  command: ["{debugger}", -nx, -q, "{prog}", -ex, "core-file {core}"]
```

Add a recipe beside `xtensa-esp.sh` to assemble the package, and
`toolchains/recipes/verify.py` will check it: required keys, a debugger that
runs, an interpreter that starts, a complete library closure, every path-valued
environment variable resolving inside the package, and every placeholder known.

Why that verification is not optional: Xtensa is a *configurable* architecture,
and the same gdb binary yields a correct backtrace or confident nonsense
depending on the core configuration it is handed — reporting `xtensa` either
way. A missing `XTENSA_GNU_CONFIG` produced `0x84870840 in ?? ()` where the
batch decode of the same core resolved every frame. Nothing errored. That class
of failure is what the guards exist for.

### Why the interpreter is bundled

`esp-coredump` is a Python program, and its extension modules `dlopen`
libraries that `ldd` on the interpreter never reveals — `binascii` needing libz
is the one that bit. The old answer was to bind `/lib/<multiarch>` wholesale
into the conversion jail. A package carries a relocatable CPython with those
libraries inside it, so the jail's entire external need is nine glibc libraries
and the wholesale bind is gone. An integration test asserts no whole directory
is bound from outside a package unless its descriptor asked for it by name.
