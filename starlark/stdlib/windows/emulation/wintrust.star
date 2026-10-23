"""Bounded Authenticode verification for an explicitly disconnected machine."""

def offline_wintrust_plugin(files, roots, disallowed, unix_time, policy_flags):
    """Verify embedded signatures using explicit media roots, time and policy.

    Models generic verify-v2 FILE/VERIFY/CLOSE, no UI, chain revocation and
    cache-only retrieval (0x1440), with an empty revocation cache. The supported
    Windows policy 0x23c00 permits offline revocation for individual/commercial
    publishers and ignores timestamp revocation. Both chains still undergo
    signature, time, purpose and explicit-root validation. No host trust/clock
    or network is consulted. Disallowed certificates are never accepted.

    Unsupported formats, policies and invalid cryptographic inputs stop
    execution, rather than falsely reporting successful trust. Provider-state
    inspection is limited to borrowed signer/chain/DER views (no CERT_INFO or
    CMSG_SIGNER_INFO). This is not a general WinTrust provider.
    """
    if policy_flags != 0x23c00:
        fail("offline WinTrust requires the explicitly supplied supported Windows policy 0x23c00")
    if unix_time <= 0:
        fail("offline WinTrust requires an explicit positive verification time")
    def key(path):
        return path.replace("/", "\\").lower()
    inputs = {}
    for path, value in files.items():
        if key(path) in inputs:
            fail("ambiguous WinTrust file path")
        inputs[key(path)] = value
    state = {"files": inputs, "roots": list(roots), "disallowed": list(disallowed),
             "unix_time": unix_time, "policy_flags": policy_flags, "handles": {}, "checks": [], "providers": {}, "chains": {}, "certificates": {}}
    # These borrowed views live until WTD_STATEACTION_CLOSE. They expose only
    # the validated chains; message/store handles and CERT_INFO are not modeled.
    def provider_view(m, check, data, action, parent):
        allocations = []
        def alloc(size = 0, value = None):
            p = m.allocate(value = value) if value != None else m.allocate(size = size)
            allocations.append(p)
            return p
        def record(fields):
            offset = 0
            alignment = 4
            offsets = []
            for kind, value in fields:
                width = m.pointer_size if kind == "p" else 4
                alignment = max(alignment, width)
                offset = (offset + width - 1) // width * width
                offsets.append(offset)
                offset += width
            size = (offset + alignment - 1) // alignment * alignment
            p = alloc(size = size)
            for i in range(len(fields)):
                kind, value = fields[i]
                if kind == "p":
                    m.write_pointer(p + offsets[i], value)
                else:
                    m.write_u32le(p + offsets[i], size if kind == "size" else value)
            return p
        def pointers(values):
            p = alloc(size = len(values) * m.pointer_size)
            for i in range(len(values)):
                m.write_pointer(p + i * m.pointer_size, values[i])
            return p
        def signer(chains, counter = 0, timestamp = False):
            if len(chains) != 1:
                fail("WinTrust provider view requires one unambiguous validated path")
            chain = chains[0]
            elements = []
            certs = []
            for i in range(len(chain)):
                der = chain[i]
                parsed = windows.certificate(der)
                context = record([("d", 1), ("p", alloc(value = der)), ("d", len(der)), ("p", 0), ("p", 0)])
                state["certificates"][context] = der
                check["certificates"].append(context)
                # Exclude the trust anchor from the unavailable revocation check.
                error = 0 if i == len(chain) - 1 else 0x01000040
                element = record([("size", 0), ("p", context), ("d", error), ("d", 0),
                                  ("p", 0), ("p", 0), ("p", 0), ("p", 0)])
                elements.append(element)
                certs.append(record([("size", 0), ("p", context), ("d", 0),
                                     ("d", 1 if i == len(chain) - 1 else 0),
                                     ("d", 1 if parsed.self_signed else 0), ("d", 0), ("d", 0),
                                     ("d", 0x11000000), ("d", 0), ("p", 0), ("d", 0),
                                     ("p", 0), ("d", 0), ("d", 0), ("p", element)]))
            cert_size = m.read_u32le(certs[0])
            cert_array = alloc(size = len(certs) * cert_size)
            for i in range(len(certs)):
                m.write(cert_array + i * cert_size, m.read(certs[i], cert_size))
            error = 0x01000040 if len(chain) > 1 else 0
            simple = record([("size", 0), ("d", error), ("d", 0), ("d", len(elements)),
                             ("p", pointers(elements)), ("p", 0), ("d", 0), ("d", 0)])
            context = record([("size", 0), ("d", error), ("d", 0), ("d", 1),
                              ("p", pointers([simple])), ("d", 0), ("p", 0), ("d", 0), ("d", 0),
                              ("d", 0), ("d", 0), ("d", 0), ("d", 0), ("d", 0)])
            state["chains"][context] = chain
            check["contexts"].append(context)
            ft = (check["signature_time"] + 11644473600) * 10000000
            return record([("size", 0), ("d", ft & 0xffffffff), ("d", ft >> 32),
                           ("d", len(chain)), ("p", cert_array), ("d", 0x10 if timestamp else 0),
                           ("p", 0), ("d", check["result"]), ("d", 1 if counter else 0),
                           ("p", counter), ("p", context)])
        check["certificates"] = []
        check["contexts"] = []
        counter = signer(check["timestamp_chains"], timestamp = True) if check["timestamp_chains"] else 0
        primary = signer(check["chains"], counter = counter)
        provider = record([("size", 0), ("p", data), ("d", 0), ("p", parent), ("p", action), ("p", 0),
                           ("d", check["result"]), ("d", 0), ("d", state["policy_flags"]), ("p", 0),
                           ("d", 0), ("p", 0), ("d", 0), ("p", 0), ("d", 0x10001), ("p", 0),
                           ("d", 1), ("p", primary), ("d", 0), ("p", 0), ("d", 0), ("p", 0),
                           ("p", 0), ("d", 0), ("d", 0), ("d", 0), ("p", 0), ("d", 0),
                           ("d", check["result"]), ("p", 0), ("d", 0), ("d", 0), ("p", 0), ("p", 0)])
        check["allocations"] = allocations
        check["provider"] = provider
        state["providers"][provider] = {"signer": primary, "counter": counter}
        return provider
    def provider_data(event):
        check = state["handles"].get(event.args[0])
        if check == None:
            return 0
        if "provider" not in check:
            provider_view(event.machine, check, check["data"], check["action"], check["parent"])
        return check["provider"]
    def provider_signer(event):
        provider, index, counter, counter_index = event.args
        entry = state["providers"].get(provider)
        if entry == None or index != 0:
            return 0
        if counter:
            return entry["counter"] if counter_index == 0 else 0
        return entry["signer"]
    def chain_policy(event):
        m = event.machine
        policy, context, para, status = event.args
        if policy != 7:
            fail("offline WinTrust only models the bounded Microsoft-root policy")
        if context not in state["chains"]:
            fail("chain policy requires a live verified WinTrust chain")
        wide = m.pointer_size == 8
        if not para or not status or m.read_u32le(para) != (16 if wide else 12) or m.read_u32le(status) not in [0, 24 if wide else 20]:
            fail("invalid chain-policy structure size")
        flags = m.read_u32le(para + 4)
        if flags not in [0, 0x10000] or m.read_pointer(para + 8) or m.read_pointer(status + 16):
            fail("unsupported Microsoft-root chain-policy options")
        # Bounded production anchor set. Enabling test roots does not make
        # arbitrary supplied roots Microsoft roots. Other anchors fail closed.
        root = windows.certificate(state["chains"][context][-1])
        accepted = root.sha256 == "df545bf919a2439c36983b54cdfc903dfa4f37d3996d8d84b4c31eec6f3c163e"
        m.write_u32le(status + 4, 0 if accepted else 0x800b0109)
        m.write_u32le(status + 8, 0)
        m.write_u32le(status + 12, 0 if accepted else len(state["chains"][context]) - 1)
        return 1  # BOOL reports policy evaluation, not its trust decision.
    def verify(event):
        m = event.machine
        action, data = event.args[1], event.args[2]
        wide = m.pointer_size == 8
        size = 88 if wide else 52
        if not action or not data or m.read_u32le(data) != size:
            return 0x80070057  # E_INVALIDARG
        if m.read(action, 16) != b"\x6b\xc5\xaa\x00\x44\xcd\xd0\x11\x8c\xc2\x00\xc0\x4f\xc2\x95\xee":
            fail("unsupported WinTrust action GUID")
        state_offset, handle_offset = (48, 56) if wide else (28, 32)
        operation = m.read_u32le(data + state_offset)
        handle = m.read_pointer(data + handle_offset)
        if operation == 2:  # WTD_STATEACTION_CLOSE
            if handle not in state["handles"]:
                return 0x80070057
            check = state["handles"].pop(handle)
            for context in check.get("contexts", []):
                state["chains"].pop(context)
            for context in check.get("certificates", []):
                state["certificates"].pop(context)
            if "provider" in check:
                state["providers"].pop(check["provider"])
            for pointer in reversed(check.get("allocations", [])):
                m.free(pointer)
            m.free(handle)
            m.write_pointer(data + handle_offset, 0)
            return 0
        if operation != 1 or handle:
            fail("unsupported WinTrust state operation")
        ui, revocation, choice = (24, 28, 32) if wide else (12, 16, 20)
        flags, context, settings = (72, 76, 80) if wide else (40, 44, 48)
        if (m.read_u32le(data + ui) != 2 or m.read_u32le(data + revocation) != 1 or
            m.read_u32le(data + choice) != 1 or m.read_u32le(data + flags) != 0x1440 or
            m.read_u32le(data + context) != 0 or m.read_pointer(data + settings) or
            m.read_pointer(data + (8 if wide else 4)) or m.read_pointer(data + (16 if wide else 8)) or
            m.read_pointer(data + (64 if wide else 36))):
            fail("unsupported WinTrust file verification options")
        info = m.read_pointer(data + (40 if wide else 24))
        if not info or m.read_u32le(info) != (32 if wide else 16):
            return 0x80070057
        path_pointer = m.read_pointer(info + (8 if wide else 4))
        if not path_pointer:
            return 0x80070057
        if m.read_pointer(info + (16 if wide else 8)) or m.read_pointer(info + (24 if wide else 12)):
            fail("WinTrust file handles and known-subject hints are not modeled")
        path = m.read_cstring(path_pointer, encoding = "utf16le")
        if key(path) not in state["files"]:
            fail("WinTrust requires the actual bytes of the requested file: " + path)
        signature = windows.pe_signature(state["files"][key(path)])
        at = state["unix_time"]
        timestamp_chains = []
        if signature.timestamp != None:
            ts = signature.timestamp
            if ts.unix > at:
                fail("WinTrust timestamp is in the future")
            timestamp_chains = windows.certificate_chain(ts.signer, state["roots"], ts.certificates, ts.unix, "timestamping")
            at = ts.unix
        chains = windows.certificate_chain(signature.signer, state["roots"], signature.certificates, at, "code_signing")
        result = 0
        for chain in chains + timestamp_chains:
            for certificate in chain:
                if certificate in state["disallowed"]:
                    result = 0x800b0111  # TRUST_E_EXPLICIT_DISTRUST
        check = {"path": path, "result": result, "policy_flags": state["policy_flags"],
                 "verification_time": state["unix_time"], "signature_time": at,
                 "chains": chains, "timestamp_chains": timestamp_chains,
                 "data": data, "action": action, "parent": event.args[0],
                 "revocation": "unavailable-offline", "revocation_checked": False}
        handle = m.allocate(size = m.pointer_size, name = "wintrust-state")
        state["handles"][handle] = check
        state["checks"].append(check)
        m.write_pointer(data + handle_offset, handle)
        return result
    def install(machine):
        machine.provide_export(chain_policy, module = "crypt32.dll", name = "CertVerifyCertificateChainPolicy", argc = 4)
        machine.provide_export(provider_data, module = "wintrust.dll", name = "WTHelperProvDataFromStateData", argc = 1)
        machine.provide_export(provider_signer, module = "wintrust.dll", name = "WTHelperGetProvSignerFromChain", argc = 4)
        for name in ["WinVerifyTrust", "WinVerifyTrustEx"]:
            machine.provide_export(verify, module = "wintrust.dll", name = name, argc = 3)
    return emulator.plugin(install, name = "windows.wintrust.offline", state = state)
