"""Semantic CryptoAPI and WinTrust registration contracts.

The plugin consumes public registration structures passed by a target export.
It does not execute CRYPT32 or WINTRUST implementation DLLs.
"""

load("@stdlib//windows:certstore.star", "certificate_store_patch")

_TRUST_STAGES = [
    "Initialization",
    "Message",
    "Signature",
    "Certificate",
    "CertCheck",
    "FinalPolicy",
    "DiagnosticPolicy",
    "Cleanup",
]

_SIP_FUNCTIONS = [
    "CryptSIPDllIsMyFileType",
    "CryptSIPDllGetSignedDataMsg",
    "CryptSIPDllPutSignedDataMsg",
    "CryptSIPDllCreateIndirectData",
    "CryptSIPDllVerifyIndirectData",
    "CryptSIPDllRemoveSignedDataMsg",
    "CryptSIPDllIsMyFileType2",
]

_CRYPTOAPI_SIGNATURES = {
    "cryptacquirecontexta": 5,
    "cryptacquirecontextw": 5,
    "cryptcreatehash": 5,
    "cryptdestroyhash": 1,
    "cryptdestroykey": 1,
    "cryptgenrandom": 3,
    "cryptgethashparam": 5,
    "crypthashdata": 4,
    "cryptimportkey": 6,
    "cryptreleasecontext": 2,
    "cryptverifysignaturea": 6,
    "cryptverifysignaturew": 6,
}

_CRYPT_VERIFYCONTEXT = 0xf0000000
# CryptImportKey accepts these documented policy flags for public-key blobs.
# They affect key persistence, export, or private-key operations, so the
# isolated verification-only provider records them without changing the
# imported RSA public key.
_PUBLIC_KEY_IMPORT_FLAGS = 0x00004153
_HASH_ALGORITHMS = {
    0x8003: ("md5", binary.decode("3020300c06082a864886f70d020505000410", encoding = "hex")),
    0x8004: ("sha1", binary.decode("3021300906052b0e03021a05000414", encoding = "hex")),
    0x800c: ("sha256", binary.decode("3031300d060960864801650304020105000420", encoding = "hex")),
    0x800d: ("sha384", binary.decode("3041300d060960864801650304020205000430", encoding = "hex")),
    0x800e: ("sha512", binary.decode("3051300d060960864801650304020305000440", encoding = "hex")),
}

def _cryptoapi_provider_module(name):
    normalized = name.replace("/", "\\").split("\\")[-1].lower()
    return normalized == "advapi32.dll" or normalized.startswith("api-ms-win-security-cryptoapi-") or normalized.startswith("ext-ms-win-security-cryptoapi-")

def _reversed_bytes(value):
    value = binary.view(value)
    output = binary.builder(capacity = len(value))
    for index in range(len(value) - 1, -1, -1):
        output.u8(binary.read_u8(value, index))
    return output.bytes()

def _pkcs1_digest_matches(encoded, digest, prefix):
    """Checks strict EMSA-PKCS1-v1_5 padding around one known digest type."""
    encoded = binary.view(encoded)
    trailer = binary.view(binary.concat([prefix, digest]))
    padding = len(encoded) - len(trailer) - 3
    if padding < 8 or not crypto.constant_time_equal(encoded[:2], b"\x00\x01") or not crypto.constant_time_equal(encoded[2 + padding:3 + padding], b"\x00") or not crypto.constant_time_equal(encoded[3 + padding:], trailer):
        return False
    return crypto.constant_time_equal(encoded[2:2 + padding], b"\xff" * padding)

def cryptoapi_plugin(kernel = None):
    """Models bounded legacy CryptoAPI provider contexts.

    Verification contexts are process-local handles. Random output is derived
    deterministically from the provider facts and a monotonic counter so
    emulation remains reproducible; it is not exposed as a cryptographic host
    randomness service.
    """
    state = {"providers": {}, "hashes": {}, "keys": {}, "next_handle": 0x70000, "actions": []}

    def fail(code):
        if kernel != None:
            kernel.state["last_error"] = code
        return 0

    def string(machine, address, wide):
        return machine.read_cstring(address, encoding = "utf16le" if wide else "ascii") if address else ""

    def callback(event):
        name = event.name.lower()
        args = event.args
        machine = event.machine
        if name in ["cryptacquirecontexta", "cryptacquirecontextw"]:
            output, container_address, provider_address, provider_type, flags = args
            if not output:
                return fail(87)
            context = {
                "container": string(machine, container_address, name.endswith("w")),
                "provider": string(machine, provider_address, name.endswith("w")),
                "provider_type": provider_type,
                "flags": flags,
                "counter": 0,
            }
            # The isolated model has no persistent key container store. Fail
            # closed unless the caller explicitly requests an ephemeral
            # verification context.
            if (flags & _CRYPT_VERIFYCONTEXT) != _CRYPT_VERIFYCONTEXT:
                return fail(0x80090016)  # NTE_BAD_KEYSET
            handle = state["next_handle"]
            state["next_handle"] = handle + 1
            state["providers"][handle] = context
            state["actions"].append(dict(context, operation = "acquire", handle = handle))
            machine.write_u32le(output, handle)
            if kernel != None:
                kernel.state["last_error"] = 0
            return 1
        if name == "cryptreleasecontext":
            context = state["providers"].pop(args[0], None)
            if context == None:
                return fail(6)
            state["actions"].append({"operation": "release", "handle": args[0]})
            if kernel != None:
                kernel.state["last_error"] = 0
            return 1
        if name == "cryptgenrandom":
            context = state["providers"].get(args[0])
            size = args[1]
            if context == None:
                return fail(6)
            if size > (1 << 20) or (size and not args[2]):
                return fail(87)
            output = binary.builder(capacity = size)
            while output.size < size:
                seed = binary.builder()
                seed.u32le(args[0])
                seed.u32le(context["counter"])
                seed.u32le(context["provider_type"])
                seed.append(binary.encode(context["provider"], encoding = "utf16le", nul = True))
                output.append(crypto.hash("sha256", seed.bytes()))
                context["counter"] += 1
            machine.write(args[2], output.bytes()[:size])
            state["actions"].append({"operation": "random", "handle": args[0], "size": size})
            if kernel != None:
                kernel.state["last_error"] = 0
            return 1
        if name == "cryptcreatehash":
            provider, algorithm, key, flags, output = args
            specification = _HASH_ALGORITHMS.get(algorithm)
            if provider not in state["providers"]:
                return fail(6)  # ERROR_INVALID_HANDLE
            if specification == None:
                return fail(0x80090008)  # NTE_BAD_ALGID
            if key or flags or not output:
                return fail(0x80090009 if flags else 87)  # NTE_BAD_FLAGS / ERROR_INVALID_PARAMETER
            handle = state["next_handle"]
            state["next_handle"] = handle + 1
            state["hashes"][handle] = {
                "algorithm": algorithm,
                "hasher": crypto.hasher(specification[0]),
                "provider": provider,
            }
            machine.write_u32le(output, handle)
            state["actions"].append({"operation": "create-hash", "handle": handle, "algorithm": algorithm})
            if kernel != None:
                kernel.state["last_error"] = 0
            return 1
        if name == "crypthashdata":
            current = state["hashes"].get(args[0])
            if current == None:
                return fail(0x80090002)  # NTE_BAD_HASH
            if args[3] or args[2] > (16 << 20) or (args[2] and not args[1]):
                return fail(0x80090009 if args[3] else 87)
            current["hasher"].update(machine.read(args[1], args[2]) if args[2] else b"")
            state["actions"].append({"operation": "hash-data", "handle": args[0], "size": args[2]})
            if kernel != None:
                kernel.state["last_error"] = 0
            return 1
        if name == "cryptgethashparam":
            current = state["hashes"].get(args[0])
            if current == None:
                return fail(0x80090002)
            digest = current["hasher"].sum()
            if args[1] == 1:  # HP_ALGID
                value = binary.u32le(current["algorithm"])
            elif args[1] == 2:  # HP_HASHVAL
                value = digest
            elif args[1] == 4:  # HP_HASHSIZE
                value = binary.u32le(len(digest))
            else:
                return fail(87)
            if not args[3]:
                return fail(87)
            capacity = machine.read_u32le(args[3])
            machine.write_u32le(args[3], len(value))
            action = {
                "operation": "get-hash-param",
                "handle": args[0],
                "parameter": args[1],
                "capacity": capacity,
                "size": len(value),
                "output": bool(args[2]),
            }
            if args[2]:
                if capacity < len(value):
                    action["result"] = 234
                    state["actions"].append(action)
                    return fail(234)  # ERROR_MORE_DATA
                machine.write(args[2], value)
            action["result"] = 0
            state["actions"].append(action)
            if kernel != None:
                kernel.state["last_error"] = 0
            return 1
        if name == "cryptdestroyhash":
            if state["hashes"].pop(args[0], None) == None:
                return fail(0x80090002)
            state["actions"].append({"operation": "destroy-hash", "handle": args[0]})
            if kernel != None:
                kernel.state["last_error"] = 0
            return 1
        if name == "cryptimportkey":
            provider, data_address, size, parent, flags, output = args
            if provider not in state["providers"]:
                return fail(6)
            if parent or flags & ~_PUBLIC_KEY_IMPORT_FLAGS or not output or not data_address or size < 20 or size > (1 << 20):
                return fail(87)
            data = machine.read(data_address, size)
            if binary.read_u8(data, 0) != 0x06 or binary.read_u8(data, 1) != 0x02 or binary.read_u16le(data, 2) != 0 or binary.read_u32le(data, 8) != 0x31415352:
                return fail(0x8009000a)  # NTE_BAD_TYPE
            bits = binary.read_u32le(data, 12)
            exponent = binary.read_u32le(data, 16)
            if bits < 384 or bits > 16384 or bits % 8 or len(data) != 20 + bits // 8 or exponent < 3 or exponent % 2 == 0:
                return fail(0x80090005)  # NTE_BAD_DATA
            handle = state["next_handle"]
            state["next_handle"] = handle + 1
            state["keys"][handle] = {
                "algorithm": binary.read_u32le(data, 4),
                "exponent": binary.u32le(exponent),
                "flags": flags,
                "modulus": data[20:],
                "provider": provider,
            }
            machine.write_u32le(output, handle)
            state["actions"].append({"operation": "import-public-key", "handle": handle, "bits": bits, "flags": flags})
            if kernel != None:
                kernel.state["last_error"] = 0
            return 1
        if name == "cryptdestroykey":
            if state["keys"].pop(args[0], None) == None:
                return fail(0x80090003)  # NTE_BAD_KEY
            state["actions"].append({"operation": "destroy-key", "handle": args[0]})
            if kernel != None:
                kernel.state["last_error"] = 0
            return 1
        if name in ["cryptverifysignaturea", "cryptverifysignaturew"]:
            current = state["hashes"].get(args[0])
            key = state["keys"].get(args[3])
            if current == None:
                return fail(0x80090002)
            if key == None:
                return fail(0x80090003)
            if args[5] or args[2] != len(key["modulus"]) or not args[1]:
                return fail(0x80090009 if args[5] else 0x80090004)  # NTE_BAD_FLAGS / NTE_BAD_LEN
            signature = machine.read(args[1], args[2])
            decoded = crypto.mod_exp(signature, key["exponent"], key["modulus"], byte_order = "little")
            specification = _HASH_ALGORITHMS[current["algorithm"]]
            valid = _pkcs1_digest_matches(_reversed_bytes(decoded), current["hasher"].sum(), specification[1])
            state["actions"].append({"operation": "verify-signature", "hash": args[0], "key": args[3], "valid": valid})
            if not valid:
                return fail(0x80090006)  # NTE_BAD_SIGNATURE
            if kernel != None:
                kernel.state["last_error"] = 0
            return 1
        return 0

    def install(machine):
        for name, argc in _CRYPTOAPI_SIGNATURES.items():
            machine.provide_export(callback, module = "advapi32.dll", name = name, argc = argc)
        for imported in machine.imports:
            name = imported.name.lower()
            if _cryptoapi_provider_module(imported.module) and name in _CRYPTOAPI_SIGNATURES:
                machine.hook(callback, address = imported.address, argc = _CRYPTOAPI_SIGNATURES[name])

    return emulator.plugin(install, name = "windows.cryptoapi", state = state)

def _hex(value, width):
    text = hex(value)[2:].upper()
    return "0" * (width - len(text)) + text

def _guid(machine, address):
    cursor = binary.cursor(machine.read(address, 16))
    return "{%s-%s-%s-%s-%s}" % (
        _hex(cursor.u32le(), 8),
        _hex(cursor.u16le(), 4),
        _hex(cursor.u16le(), 4),
        hex(cursor.bytes(2)).upper(),
        hex(cursor.bytes(6)).upper(),
    )

def _string(machine, address, wide = False):
    if not address:
        return ""
    return machine.read_cstring(address, encoding = "utf16le" if wide else "ascii")

def _set(registry, key, name, value):
    registry.set_value(hive = "SOFTWARE", key = key, name = name, type = "REG_SZ", value = value)

def crypto_registration_plugin(registry, module, file = None):
    """Models WinTrust action, default-usage, SIP, and OID registration."""
    state = {"next_store": 0x68000, "stores": {}, "system_stores": {}, "contexts": {}, "actions": []}

    def certificate_records(data):
        return [
            {"der": certificate.der, "sha1": certificate.sha1, "record": certificate}
            for certificate in windows.pkcs7_certificates(data)
        ]

    def persist_certificate(store, certificate):
        name = store["name"].upper()
        if name not in ["ROOT", "CA"]:
            return
        patch = certificate_store_patch(certificate["record"], store = name)
        registry.set_value(patch["hive"], patch["key"], patch["name"], patch["type"], patch["value"])

    def open_system_store(event):
        wide = event.name.lower().endswith("w")
        name = _string(event.machine, event.args[1], wide = wide)
        if not name:
            return 0
        handle = state["next_store"]
        state["next_store"] = handle + 1
        certificates = state["system_stores"].get(name.lower())
        if certificates == None:
            certificates = []
            state["system_stores"][name.lower()] = certificates
        state["stores"][handle] = {"name": name, "certificates": certificates}
        state["actions"].append({"kind": "open_store", "name": name, "handle": handle})
        return handle

    def register_system_store(event):
        # CERT_SYSTEM_STORE_RELOCATE_FLAG changes the first argument to a
        # structure. Setup's InitPKI path registers ordinary local named stores
        # and passes the reserved arguments as NULL.
        if event.args[1] & 0x80000000:
            return 0
        name = _string(event.machine, event.args[0], wide = True)
        if not name or event.args[2] or event.args[3]:
            return 0
        if name.lower() not in state["system_stores"]:
            state["system_stores"][name.lower()] = []
        state["actions"].append({"kind": "register_system_store", "name": name, "flags": event.args[1]})
        return 1

    def open_store(event):
        provider = event.args[0]
        parameter = event.args[4]
        serialized = None
        if provider in [6] and parameter:
            size = event.machine.read_u32le(parameter)
            address = event.machine.read_u32le(parameter + 4)
            serialized = event.machine.read(address, size) if address and size else b""
            name = "serialized"
        elif provider in [9, 10, 12, 13] and parameter:
            name = _string(event.machine, parameter, wide = provider in [10, 13])
        elif provider <= 0xffff:
            name = "provider-%d" % provider
        else:
            name = _string(event.machine, provider)
        if not name:
            return 0
        handle = state["next_store"]
        state["next_store"] = handle + 1
        if serialized != None:
            certificates = certificate_records(serialized)
        else:
            certificates = state["system_stores"].get(name.lower())
            if certificates == None:
                certificates = []
                state["system_stores"][name.lower()] = certificates
        state["stores"][handle] = {"name": name, "certificates": certificates}
        state["actions"].append({"kind": "open_store", "name": name, "provider": provider, "handle": handle, "certificates": len(certificates)})
        return handle

    def close_store(event):
        if event.args[0] not in state["stores"]:
            return 0
        state["stores"].pop(event.args[0])
        return 1

    def certificate_context(machine, store_handle, index):
        store = state["stores"].get(store_handle)
        if store == None or index < 0 or index >= len(store["certificates"]):
            return 0
        certificate = store["certificates"][index]
        data = machine.allocate(size = len(certificate["der"]), value = certificate["der"], name = "crypt32.certificate")
        context = machine.allocate(size = 20, name = "crypt32.certificate-context")
        descriptor = binary.builder(capacity = 20)
        descriptor.u32le(1)  # X509_ASN_ENCODING
        descriptor.u32le(data)
        descriptor.u32le(len(certificate["der"]))
        descriptor.u32le(0)  # Parsed CERT_INFO is not observed during setup.
        descriptor.u32le(store_handle)
        machine.write(context, descriptor.bytes())
        state["contexts"][context] = {"store": store_handle, "index": index, "data": data}
        return context

    def enumerate_certificates(event):
        store = state["stores"].get(event.args[0])
        if store == None:
            return 0
        previous = event.args[1]
        index = state["contexts"].get(previous, {}).get("index", -1) + 1 if previous else 0
        if index >= len(store["certificates"]):
            return 0
        return certificate_context(event.machine, event.args[0], index)

    def find_certificate(event):
        store = state["stores"].get(event.args[0])
        if store == None:
            return 0
        previous = event.args[5]
        index = state["contexts"].get(previous, {}).get("index", -1) + 1 if previous else 0
        return certificate_context(event.machine, event.args[0], index)

    def enumerate_crls(event):
        # Embedded Win98 root bundles contain certificates; an empty CRL
        # sequence is a valid store result and terminates enumeration.
        return 0

    def add_encoded_certificate(event):
        store = state["stores"].get(event.args[0])
        if store == None or not event.args[2] or not event.args[3]:
            return 0
        encoded = event.machine.read(event.args[2], event.args[3])
        records = certificate_records(encoded)
        if not records:
            return 0
        certificate = records[0]
        store["certificates"].append(certificate)
        persist_certificate(store, certificate)
        context = certificate_context(event.machine, event.args[0], len(store["certificates"]) - 1)
        if event.args[6]:
            event.machine.write_u32le(event.args[6], context)
        state["actions"].append({"kind": "add_certificate", "store": store["name"], "size": len(certificate), "disposition": event.args[4]})
        return 1

    def add_certificate_context(event):
        destination = state["stores"].get(event.args[0])
        source = state["contexts"].get(event.args[1])
        if destination == None or source == None:
            return 0
        source_store = state["stores"].get(source["store"])
        if source_store == None or source["index"] >= len(source_store["certificates"]):
            return 0
        certificate = source_store["certificates"][source["index"]]
        index = -1
        for candidate_index, candidate in enumerate(destination["certificates"]):
            if candidate["sha1"] == certificate["sha1"]:
                index = candidate_index
                break
        if index < 0:
            destination["certificates"].append(certificate)
            index = len(destination["certificates"]) - 1
        persist_certificate(destination, certificate)
        context = certificate_context(event.machine, event.args[0], index)
        if event.args[3]:
            event.machine.write_u32le(event.args[3], context)
        state["actions"].append({"kind": "add_certificate", "store": destination["name"], "fingerprint": certificate["sha1"], "disposition": event.args[2]})
        return 1

    def certificate_property(event):
        context = state["contexts"].get(event.args[0])
        if context == None or not event.args[3]:
            return 0
        store = state["stores"].get(context["store"])
        if store == None or context["index"] >= len(store["certificates"]):
            return 0
        certificate = store["certificates"][context["index"]]
        property_id = event.args[1]
        if property_id in [3, 20]:  # SHA1_HASH / KEY_IDENTIFIER
            value = binary.decode(certificate["sha1"], encoding = "hex")
        elif property_id == 4:  # MD5_HASH
            value = crypto.hash("md5", certificate["der"])
        elif property_id == 14:  # ACCESS_STATE
            value = binary.u32le(0)
        else:
            return 0
        capacity = event.machine.read_u32le(event.args[3])
        event.machine.write_u32le(event.args[3], len(value))
        if not event.args[2]:
            return 1
        if capacity < len(value):
            return 0
        event.machine.write(event.args[2], value)
        return 1

    def delete_certificate(event):
        address = event.args[0]
        context = state["contexts"].get(address)
        if context == None:
            return 0
        store = state["stores"].get(context["store"])
        if store == None or context["index"] >= len(store["certificates"]):
            return 0
        certificate = store["certificates"].pop(context["index"])
        name = store["name"].upper()
        if name in ["ROOT", "CA"]:
            patch = certificate_store_patch(certificate["record"], store = name)
            registry.delete_value(patch["hive"], patch["key"], patch["name"])
        state["actions"].append({"kind": "delete_certificate", "store": store["name"], "fingerprint": certificate["sha1"]})
        free_certificate(event)
        return 1

    def free_certificate(event):
        context = state["contexts"].pop(event.args[0], None)
        if context != None:
            event.machine.free(context["data"])
            event.machine.free(event.args[0])
        return 1

    def protect_function(event):
        # Win98's private CryptoAPI entry point takes seven DWORD arguments.
        # InitPKI uses function class 2 with no replacement callbacks to ask
        # CryptoAPI to protect its built-in certificate dispatch. There is no
        # host function pointer in the isolated registrar, but the successful
        # protection state remains observable for diagnostics.
        state["actions"].append({"kind": "protect_function", "class": event.args[0], "flags": event.args[1]})
        return 1

    def register_trust(event):
        action = _guid(event.machine, event.args[0])
        info = event.args[2]
        if event.machine.read_u32le(info) < 4 + len(_TRUST_STAGES) * 12:
            return 0
        for index, stage in enumerate(_TRUST_STAGES):
            entry = info + 4 + index * 12
            dll = _string(event.machine, event.machine.read_u32le(entry + 4), wide = True)
            function = _string(event.machine, event.machine.read_u32le(entry + 8), wide = True)
            if dll and function:
                key = "/Microsoft/Cryptography/Providers/Trust/%s/%s" % (stage, action)
                _set(registry, key, "$DLL", dll)
                _set(registry, key, "$Function", function)
        return 1

    def register_sip(event):
        info = event.args[0]
        if event.machine.read_u32le(info) < 0x2c:
            return 0
        subject_pointer = event.machine.read_u32le(info + 4)
        if not subject_pointer:
            return 0
        subject = _guid(event.machine, subject_pointer)
        dll = _string(event.machine, event.machine.read_u32le(info + 8), wide = True) or module
        for index, function_key in enumerate(_SIP_FUNCTIONS):
            function = _string(event.machine, event.machine.read_u32le(info + 0x10 + index * 4), wide = True)
            if function:
                key = "/Microsoft/Cryptography/OID/EncodingType 0/%s/%s" % (function_key, subject)
                _set(registry, key, "Dll", dll)
                _set(registry, key, "FuncName", function)
        return 1

    def register_oid(event):
        encoding, function_pointer, oid_pointer, dll_pointer, override_pointer = event.args
        function = _string(event.machine, function_pointer)
        if not function:
            return 0
        oid = "#%d" % oid_pointer if oid_pointer <= 0xffff else _string(event.machine, oid_pointer)
        dll = _string(event.machine, dll_pointer, wide = True) or module
        if not oid or not dll:
            return 0
        key = "/Microsoft/Cryptography/OID/EncodingType %d/%s/%s" % (encoding, function, oid)
        _set(registry, key, "Dll", dll)
        override = _string(event.machine, override_pointer)
        if override:
            _set(registry, key, "FuncName", override)
        return 1

    def register_default_usage(event):
        # The isolated runner has no pre-existing WinTrust registry state. The
        # target DLL performs the durable action registrations after this
        # setup-owned default-usage request succeeds, and those writes are
        # captured by register_trust below.
        usage = _string(event.machine, event.args[0])
        info = event.args[1]
        return 1 if usage and info and event.machine.read_u32le(info) >= 8 else 0

    def get_policy_flags(event):
        if event.args[0]:
            event.machine.write_u32le(event.args[0], 0)
        state["actions"].append({"kind": "get_policy_flags", "flags": 0})
        return None

    def set_policy_flags(event):
        state["actions"].append({"kind": "set_policy_flags", "flags": event.args[0]})
        return 1

    functions = {
        "wintrustaddactionid": (register_trust, 3),
        "wintrustadddefaultforusage": (register_default_usage, 2),
        "wintrustgetregpolicyflags": (get_policy_flags, 1),
        "wintrustsetregpolicyflags": (set_policy_flags, 1),
        "cryptsipaddprovider": (register_sip, 1),
        "cryptregisteroidfunction": (register_oid, 5),
        "certopensystemstorea": (open_system_store, 2),
        "certopensystemstorew": (open_system_store, 2),
        "certregistersystemstore": (register_system_store, 4),
        "certopenstore": (open_store, 5),
        "certclosestore": (close_store, 2),
        "certenumcertificatesinstore": (enumerate_certificates, 2),
        "certfindcertificateinstore": (find_certificate, 6),
        "certenumcrlsinstore": (enumerate_crls, 2),
        "certgetcrlfromstore": (enumerate_crls, 4),
        "certaddencodedcertificatetostore": (add_encoded_certificate, 7),
        "certaddcertificatecontexttostore": (add_certificate_context, 4),
        "certgetcertificatecontextproperty": (certificate_property, 4),
        "certdeletecertificatefromstore": (delete_certificate, 1),
        "certfreecertificatecontext": (free_certificate, 1),
        "i_certprotectfunction": (protect_function, 7),
    }
    successful_removals = {
        "cryptsipremoveprovider": 1,
        "cryptunregisteroidfunction": 3,
        "cryptunregisterdefaultoidfunction": 3,
        "wintrustremoveactionid": 1,
    }

    def remove(event):
        return 1

    def install(machine):
        for name, binding in functions.items():
            provider = "wintrust.dll" if name.startswith("wintrust") else "crypt32.dll"
            local = machine.resolve_export(module, name = name)
            machine.provide_export(binding[0], module = provider, name = name, argc = binding[1])
            if local:
                machine.hook(binding[0], address = local, argc = binding[1])
        for name, argc in successful_removals.items():
            provider = "wintrust.dll" if name == "wintrustremoveactionid" else "crypt32.dll"
            local = machine.resolve_export(module, name = name)
            machine.provide_export(remove, module = provider, name = name, argc = argc)
            if local:
                machine.hook(remove, address = local, argc = argc)
        for imported in machine.imports:
            binding = functions.get(imported.name.lower())
            if binding != None:
                machine.hook(binding[0], address = imported.address, argc = binding[1])
            elif imported.name.lower() in successful_removals:
                machine.hook(remove, address = imported.address, argc = successful_removals[imported.name.lower()])

    return emulator.plugin(install, name = "windows.crypto-registration", state = state)
