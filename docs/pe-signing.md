# In-memory PE signing

`windows.pe_sign` creates an embedded RSA/SHA-256 Authenticode signature for
PE32 and PE32+ images, including ARM64 executables and drivers. Construction,
hashing, ASN.1 encoding, signing, and checksum updates run in Go. No external
signer, OpenSSL executable, extraction step, or intermediate host file is used.

```starlark
identity = windows.signing_identity(
    certificate = certificate_file,
    private_key = private_key_file,
    chain = [intermediate_certificate_file],
)
signed = windows.pe_sign(unsigned_file, identity)
guest_files.write("/Windows/System32/drivers/example.sys", signed)
```

Certificate and key inputs accept portable files or bytes, in DER or PEM.
Keys must be unencrypted PKCS#1 or PKCS#8 RSA keys, between 2048 and 8192 bits.
The certificate must match the key and permit code signing when its key-usage
extensions constrain usage. An optional chain contains at most 16 additional
certificates. Embedding that chain does not validate its trust or validity.

For disposable test VMs, generate an identity entirely in memory:

```starlark
now = int(clock.unix())
identity = windows.test_signing_identity(
    subject = "TinyRangeX development driver",
    not_before = now - 3600,
    not_after = now + 30 * 86400,
)
signed = windows.pe_sign(unsigned_file, identity)
public_certificate = identity.certificate
```

The identity hides its private key from Starlark representations and attribute
access. It remains usable for the lifetime of the session. Generated identities
are intentionally ephemeral; use `signing_identity` with caller-managed inputs
when a key must persist. Dates are explicit Unix seconds so recipes can use
their clock abstraction rather than a hidden host clock. Signing does not
check certificate expiry or change trust stores, Secure Boot, or boot policy.

An existing certificate table is rejected by default. `replace=True` replaces
the complete table, including old signatures and timestamps, while preserving
the image and its overlay. Tables must be eight-byte aligned, structurally
bounded, outside the image sections, and at the end of the file. Malformed or
nonterminal tables are rejected rather than discarding unrelated bytes.

The output contains one PKCS#7 SignedData signer, a SHA-256 image digest,
authenticated content-type/message-digest/statement/opus attributes, and the
signer's certificate plus any supplied chain. `page_hashes=True` additionally
embeds SHA-256 Authenticode page hashes; the RAMFB test driver loads without
this optional feature. It is not timestamped and has no nested signatures.
This API does not implement PFX decryption, ECDSA signing, certificate-chain trust verification, or Microsoft
driver certification.

## Catalog packages

`windows.catalog_sign(members, identity, created_at, os_attributes="")` creates
a signed catalog entirely in memory. `members` maps simple filenames to files
or bytes. Add `CatalogFile` to the INF before passing it to the catalog signer:

```starlark
catalog = windows.catalog_sign(
    {"example.inf": inf, "example.sys": signed}, identity,
    created_at = int(clock.unix()), os_attributes = "2:10.0",
)
```

The catalog contains a version 1 CTL with SHA-256 indirect-data member digests,
uppercase hexadecimal UTF-16 subject tags, file and SIP type attributes, and
optional OSAttr attributes. It uses the same PKCS#7 signing infrastructure as
PE signatures. Filename and OSAttr strings use the catalog's prescribed
BMPString and UTF-16LE encodings. The CTL update time comes from the caller;
the list identifier is derived from its entries. Catalog construction is
deterministic for a given identity, inputs, and time.

This builder supports ordinary flat files and the headers-and-sections PE
catalog digest exposed by `catalog_hash`; it does not implement specialized
MSI or other SIP hashing. Member names are case insensitive simple filenames.
Input is bounded to 4096 members, 64 MiB per member, and 256 MiB in total.
Package selection and trust remain separate guest integration checks.

The CTL layout follows Microsoft's
[CTL_INFO](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-ctl_info)
and [CRYPTCATATTRIBUTE](https://learn.microsoft.com/en-us/windows/win32/api/mscat/ns-mscat-cryptcatattribute)
definitions. Attribute wire encodings were checked against the small original
MakeCat fixture published in Wine's `dlls/wintrust/tests/crypt.c`; no host
catalog builder is invoked. Tests independently decode the CTL and PKCS#7,
verify RSA signatures, reject changed signed attributes, check member digests
and subject types, and round-trip through the bounded catalog index parser.
A fresh Windows 11 Validation OS 26100.8521 x64 guest also accepted the generated
CC display catalog and signed driver through native `WinVerifyTrust`, both with
status zero. That check used the Authenticode policy, the installed development
certificate, no UI, and local-cache-only retrieval. The optional native PE guest
endpoint exposes the same read-only check as `verify_trust(path)`.

For modern ARM64 Windows kernel drivers, a locally generated certificate in
the trust store does not replace production kernel signing requirements.
Development drivers need test-signing mode and a signed image; guest driver
loading remains a separate integration test from constructing a valid signature.

## Format references and validation

The implementation is based on Microsoft's
[Authenticode PE specification](https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx),
[PE format specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format),
and [RFC 2315](https://www.rfc-editor.org/rfc/rfc2315), using Go's standard crypto
and ASN.1 libraries. No GPL implementation is incorporated or translated.

Two encoding details were checked against the Microsoft-signed ARM64
`Windows/Boot/EFI/bootmgfw.efi` in Validation OS build 26100.9278:
`SpcAttributeTypeAndOptionalValue.value` is encoded as a direct SEQUENCE,
and `SpcPeImageData.file` has an explicit `[0]` wrapper around its choice.
The image uses an empty flags bit string and empty Unicode file name. These
wire details differ from portions of the ASN.1 printed in the document.

The signing digest follows the dedicated Authenticode document's numbered
algorithm, including its extra-data range beginning at `SizeOfHeaders` plus
the sum of section raw sizes. This intentionally differs from the older
headers-and-sections digest exposed by `windows.catalog_hash`. Certificate
alignment padding before the table is included; the checksum, security
directory entry, and certificate table are excluded.

Tests cover PE32, AMD64 PE32+, and ARM64 PE32+; reversed section-header order;
overlay and alignment bytes; malformed tables and truncation; key mismatch;
replacement and checksum stability; and the Starlark API. An independent typed
ASN.1 decoder and `x509.Certificate.CheckSignature` validate the generated PKCS#7
signature, and separately assembled digest streams check image coverage.

```sh
go test ./windows -run 'TestPESign' -v
```

Windows kernel-loader acceptance and WinVerifyTrust policy acceptance are not
established by these unit tests.

The workspace's `scripts/inspect/pe_signing.star` constructs a disposable
Validation OS ARM64 image with the public test certificate in its machine ROOT
store. It asks WinVerifyTrust to accept a signed image and reject both a mutated
image and an unsigned control, then captures the console for manual inspection.
The development image recipe enables test-signing mode by default. This probe
checks user-mode Authenticode policy, not kernel-driver loading. Its Windows
structures explicitly use `structs.HostLayout`, including the file-info
structure reached indirectly through a pointer.

Validated on Validation OS ARM64 build 26100.9278 under QEMU/HVF on an M4
MacBook Air: WinVerifyTrust accepts the generated signature, rejects the mutated
image with `TRUST_E_BAD_DIGEST` (80096010), and rejects the unsigned control with
`TRUST_E_NOSIGNATURE` (800b0100). The console prints the three results and a
final PASS. Separately, the workspace's RAMFB kernel and desktop smokes load
a test-signed Renvo ARM64 driver with test signing enabled; the desktop smoke
confirms a 2560×1664 Windows surface. This validates that development driver
on this guest, not production kernel-signing policy or arbitrary drivers.

The Renvo prerequisite involved three independent Windows ARM64 defects:
missing mandatory `DYNAMIC_BASE` in the PE header; a nested I/O helper call
overwriting its wrapper's LR; and reversed length/offset registers in the
runtime's saved arguments. Correcting the header permits loading, preserving
LR restores return to the caller, and using x1 for length and x2 for offset
restores console writes. Definitions, generated backend code, and the bundled
compiler now agree on these fixes.

## Embedded signature integrity inspection

`windows.pe_signature(file)` accepts a PE file/bytes up to 256 MiB and verifies
one embedded RSA/SHA-256 Authenticode signature. It checks image hashing,
authenticated content attributes, signer issuer/serial binding and the RSA
signature. Certificate tables are limited to 4 MiB and 32 certificate choices.
It returns signer DER, embedded X.509 certificates, signature bytes, unsigned
attribute DER, `digest_algorithm`, and an optional `timestamp` record.

A recognized Microsoft RFC 3161 timestamp is verified cryptographically and
bound to the primary signature; its record contains `unix`, `signer` and
`certificates`. Missing timestamps return None. Duplicate timestamps, replay
onto another signature and invalid signatures fail. Other unsigned attributes
are not validated; auxiliary CMS v1 attribute certificates are not X.509 signer
certificates or trust anchors and are excluded from returned certificate lists.

**Integrity is not trust.** No chain roots, expiry, EKU policy, revocation,
timestamp-authority trust or Windows provider policy is validated by this API.
In particular, a cryptographically valid timestamp from an untrusted authority
does not establish a trusted signing time. There is no host-root lookup, hidden
clock or network access, and this result alone must not yield WinVerifyTrust
success. The original Microsoft OneDrive 25.87.0506.0001 installer exercises
both primary and timestamp integrity; that is not installation proof.

## Explicit path validation and offline Windows policy

`windows.certificate_chain(certificate, roots, intermediates, unix_time,
purpose)` validates paths using only the supplied roots, intermediate
certificates, verification time and purpose. `timestamping` requires the leaf's
EKU extension to be critical and contain only timestamping, as required by RFC
3161; `code_signing` checks code-signing usage. Neither purpose performs
revocation checking. Combining a verified timestamp with a trusted TSA path
still requires an explicit provider-policy decision.

The opt-in `windows/emulation/wintrust.star` plugin models a bounded case:
generic verify-v2 file verification, no UI, chain revocation with cache-only
retrieval (`0x1440`), no revocation cache, and explicitly supplied Windows policy
`0x23c00`. That policy permits unavailable offline revocation information for
individual/commercial publishers and ignores timestamp revocation. The plugin
checks actual image/signature integrity, timestamp binding, future timestamps,
explicit-root/time/purpose paths and the supplied disallowed certificates. It
records revocation as **unavailable**, never as successfully checked. Other
policies, unsupported inputs and malformed cryptography stop execution rather
than returning fictitious success. This is not a complete WinTrust provider or
native-error mapping; provider-state inspection is not yet implemented.

A native comparison on a fresh, networkless Windows 11 x64 build 26300.9457
image used the original OneDrive setup file, generic verify-v2, `HWND=-1`,
`dwUIChoice=2`, `fdwRevocationChecks=1`, `dwUnionChoice=1`, `dwStateAction=1`,
`dwProvFlags=0x1440`, and otherwise zero optional fields. Windows returned zero.
The unchanged effective policy was `0x23c00`; both the primary and timestamp
chains reported `0x01000040` (offline and unknown revocation), while both signer
policy errors were zero. Each path had three certificates and used signing
time 2025-05-07 07:14:59.538 UTC. CLOSE returned zero and cleared the state handle.
Thus missing revocation cache alone does not imply policy rejection under this
Windows policy. This comparison does not justify accepting revoked, untrusted,
tampered or incorrectly timestamped inputs, nor does it establish installation.

The bounded provider view preserves the unavailable/offline revocation bits in
its non-root chain elements. Microsoft-root policy 7 accepts only the explicitly
validated path ending at Microsoft Root Certificate Authority 2010 (DER SHA-256
`df545bf919a2439c36983b54cdfc903dfa4f37d3996d8d84b4c31eec6f3c163e`). This is an
intentionally incomplete anchor set, not a subject-name or arbitrary-root test.
A third fresh, networkless 26300.9457 guest confirmed that the installer's exact
policy flags `0x10000` accept this chain despite its offline revocation status.
Both a zero-initialized policy-status size and size 24 returned BOOL true, error
zero, chain/element indexes zero, and preserved the supplied size. The emulator
supports these observed status-size forms; unsupported policy options stop.
Provider views have borrowed ownership until CLOSE; CERT_INFO, CMSG_SIGNER_INFO,
message/store handles and other provider internals are not implemented.
