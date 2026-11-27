# Virtual Lab Editor

Run the editor with `trex lab` or `go run ./cmd/trex lab` from the Trex
checkout. The current guest backends use x64 Linux with access to KVM.
Open [the local editor](http://127.0.0.1:7373). A new workspace starts blank.
Use `-root` to pick a directory for its saved definition and media
configuration. The installed command embeds its built-in recipes.

**Save** retains the editable definition on the server. **Run Lab** or **Apply**
checks the draft and shows which nodes will start, stop, or rebuild. **Export**
produces a shareable JSON lab without host media bindings. Import loads it into
the draft. Choose your own media before applying.

Open a running node's display or serial console from its card. The Runtime
tab shows the guest's current phase and the login hints for domain nodes.
Open **Logs** from the toolbar to view recent diagnostics across the lab.
The Runtime tab can open the same panel filtered to the current node.
The display fits the guest picture to the window and offers a **Full screen**
control. Press Escape to release a captured relative pointer.
Select **Inspect failure** in the status bar to open the affected node's
startup details, including recipe messages and any script traceback.

Each catalog entry declares its configuration fields, media, and ports. Its
Starlark recipe composes the existing image builders and starts one node. The
lab manager owns the graph and applies changes in dependency order. Existing
smokes can still exercise the shared builders and check guest behavior.

## Local media discovery

For a mounted media collection, save a `local/lab-media.json` file in the
workspace. The `local` directory is ignored by Git.

```json
{
  "directory": "/path/to/mounted/media",
  "manifest": "lab-media-manifest.json",
  "exclude": ["private", "lost+found"],
  "names": {"linux": "Linux"}
}
```

Each visible subdirectory of `directory` becomes a library in the inspector's
**Media → Browse** picker. `exclude` omits named subdirectories. `names`
sets optional library labels, which are also used in saved media references.
Files added within a library appear when it is browsed again. Restart the
editor server to discover new top-level libraries or reload the configuration.

The optional manifest maps recipe IDs to media slots. References use a library
label followed by the path inside that library. The manifest path is relative
to the configuration file. For example, a `local/lab-media-manifest.json` can
include the following entry.

```json
{
  "debian-live": {"system": "Linux/debian-live.iso"}
}
```

The same defaults apply to new nodes, existing drafts and imported templates.
The **Media** tab shows the resolved references and can override each one.
**Use default** removes an override. Defaults are resolved by the local server
and do not become part of a shared lab export. If a default file is moved,
the apply plan asks you to locate it again.

Use `-media-config` for a different configuration file. Explicit `-media-root`
flags take precedence over the workspace default. You can combine them with an
explicit `-media-config` when the resulting library names are distinct.

## Built-in recipes and networking

Trex includes an isolated switch, a DHCP router, an Alpine serial shell,
Debian and Ubuntu live environments, Fedora rescue, MS-DOS 6.22, and
Windows 1.01. Supply original installation media where the recipe asks for it.

Open **Software** to search by program or operating system and add an
application to an existing or new compatible guest. Each guest can hold
multiple packages. Its **Software** tab shows the selection and lets you
remove packages. The next lab apply constructs the guest with all the chosen
packages. Older definitions with one application keep that selection.
**Compatibility** includes titles covered by standalone guest tests.

Connect a guest adapter to a numbered switch port. The editor shows the ports
in use and the next available one. Numbers are saved with the definition and
older graphs with a single shared port receive distinct numbers on load.

Linux profiles include an Alpine serial shell built from pinned upstream
packages, Debian and Ubuntu live media, and Fedora Server rescue media. The
original-media profiles boot the kernel and initramfs from the supplied ISO
on CC. The live system reads the same ISO through a read-only disk. These
guests can connect to the Lab's isolated switches.

The Nodes palette shows the year for fixed OS releases and orders them from
oldest to newest within each group. Live-media recipes that accept different
releases leave the year open.

### Alpine package selection

In **Alpine Linux 3.22 → Software**, search the upstream x86-64 main and
community repositories and select packages to include. Apply the lab to
resolve dependencies, verify the signed repository and package identities,
and build a fresh initramfs in memory. The serial console opens in the
resulting guest. The lab definition records the exact versions selected in
the picker. If an upstream mirror retires a selected version, select its
replacement. Packages that require an unimplemented install hook report the
package and hook during apply.

### Web Server and embedded browser

Add a **Web Server** node and apply the lab. Open its **Browser** surface to
visit the example site. To serve a different page, choose **HTML file** under
**HTTP** and bind a self-contained HTML file in **Media**. Connect the
node to an isolated switch and set a static IPv4 address or add a DHCP router
to make its HTTP service available to other guests on that segment.

The Go HTTP service runs directly on the isolated lab network and starts
without a guest OS. Set **HTTP port** under **Network** and use **HTTP
routes (JSON)** in the **HTTP** tab to add or override responses. Route
paths match exactly. A missing method defaults to GET, and a missing
status defaults to 200. Choose **Routes only** to serve just those routes.

```json
[
  {
    "method": "GET",
    "path": "/health",
    "status": 200,
    "headers": {"Content-Type": "application/json"},
    "body": "{\"ready\":true}"
  }
]
```

The sandboxed browser reaches the same service through a private in-memory
connection. Use the toolbar to go back, go forward, reload, or open another
path on the same server. Rebuilding or stopping the node closes its browser
session. The node's log records request methods, paths, and response statuses.

### IRIX on the SGI Indy

Add **IRIX 6.5.22 (SGI Indy)**. Bind the two Foundation archives, three
6.5.22 Overlay archives, and November 2003 Applications archive. The node
decodes the discs in parallel and builds an XFS disk in memory. The generated
image boots the distribution kernel directly and skips the automatic kernel
rebuild during startup. You can also select **Installed CHD disk** as the boot
media and bind an installed 6.5.22 Indy disk. Construction and startup can take
several minutes. Open **Display** and wait for the visual login, then choose a
guest account.

Start the Lab with `-prepare-irix` to boot the default six-disc image in the
background. Once the service prints `IRIX template — Ready`, applying a node
with the same media starts from the login screen. Each guest gets private RAM,
devices, and disk writes. The prepared template lives in memory and is rebuilt
when this service restarts with the flag enabled.
The native Indy backend does not depend on KVM. See the [Indy recipe and
guest controls](ip24.md#interactive-browser-desktop).

V1 Ethernet domains are isolated. A switch can connect multiple guests. Guest
networking is offered on profiles that have Ethernet configuration. Running
nodes show their configured IPv4 address or one observed on the isolated
switch. Guests using NetBEUI alone have no IPv4 address to show.

Add a **Router** and connect its **LAN** port to a switch to serve IPv4 DHCP
and DNS on that segment. DHCP clients automatically get the router's DNS
address and the `lab.test` search domain. Alpine uses DHCP when its static
address is blank. Static clients can use the router's LAN address for DNS.

DNS resolves running nodes on the same switch by node ID or a unique node
name. Labels use lowercase letters and numbers, with hyphens between words.
For example, a node named **Web Server** is reachable at `web-server.lab.test`.
Under **Network**, you can change the LAN address and prefix, the lease range
and duration, or specify a **DHCP DNS override**. The router serves the local
domain over UDP and TCP port 53.

Guest disk writes and Linux live sessions are temporary. A rebuild can discard
guest changes. The apply plan says when this will happen. Reusing a saved lab
rebuilds its guests from their definition and media.

## Deploy on your tailnet

The listener binds loopback. Configure a Tailscale Serve HTTPS proxy to its
port and pass the HTTPS origin and allowed Tailscale login.

```sh
trex lab -listen 127.0.0.1:7373 \
  -tailnet-origin "https://your-device.example.ts.net:9444" \
  -tailnet-user "your-tailscale-login"
tailscale serve --bg --https=9444 http://127.0.0.1:7373
```

Use a separate `-state` file for each workspace. Only configured media roots
are browsable. The login identifies the single editor owner in this preview.

## Extend the catalog

A Go launcher can call `labfrontend.Run` with a `labfrontend.Extension`
to register additional guest recipes, templates, software aliases and
compatibility entries. Each `lab.Recipe` declares its fields, media and
ports and names a Starlark module and function. Use an `@stdlib//` label
for embedded Trex policy or a `//` label for a module under the workspace
selected by `-root`. The module is trusted local policy. The recipe's
function receives `(kind, config, media, lan, mac, trust)` and returns a
record containing `vm` and any optional console, address or status message.

The extension can reuse a built-in guest ID to specialize its implementation.
Definitions continue to refer to the same ID. Each launcher supplies its own
set of recipe modules and original-media requirements.
