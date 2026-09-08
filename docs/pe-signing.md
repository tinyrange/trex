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
This API does not implement catalog signing,
PFX decryption, ECDSA signing, certificate-chain trust verification, or Microsoft
driver certification.

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
