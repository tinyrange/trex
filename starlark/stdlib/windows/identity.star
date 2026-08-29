"""Generic Windows machine identity policy composed from crypto primitives."""

def _validate_netbios(argument, value):
    if not value or len(value) > 15:
        error("machine_identity: %s must contain 1 to 15 characters" % argument)
    for index in range(len(value)):
        character = value[index]
        if (character >= "A" and character <= "Z") or (character >= "0" and character <= "9") or character == "-":
            continue
        error("machine_identity: %s contains invalid character %s" % (argument, repr(character)))

def _patch(hive, key, name, value):
    return {
        "hive": hive,
        "key": key,
        "name": name,
        "type": "REG_SZ",
        "value": value,
    }

def machine_identity(computer_name, workgroup = "WORKGROUP", seed = ""):
    """Builds a deterministic Windows machine SID and identity hive patches."""
    computer_name = computer_name.upper()
    workgroup = workgroup.upper()
    _validate_netbios("computer_name", computer_name)
    _validate_netbios("workgroup", workgroup)
    digest = crypto.hash("sha256", "trex/windows-machine-sid\x00" + seed + "\x00" + computer_name + "\x00" + workgroup)
    cursor = binary.cursor(digest)
    subauthorities = []
    for unused in range(3):
        value = cursor.u32le() & 0x7fffffff
        if value == 0:
            value = 1
        subauthorities.append(value)
    sid = "S-1-5-21-%d-%d-%d" % tuple(subauthorities)
    account_domain_id = "0 0 0 0 0 5 21 " + " ".join([str(value) for value in subauthorities])
    workstation = "/ControlSet001/Services/LanmanWorkstation/Parameters"
    patches = [
        _patch("SYSTEM", "/ControlSet001/Control/ComputerName/ComputerName", "ComputerName", computer_name),
        _patch("SYSTEM", "/ControlSet001/Control/ComputerName/ActiveComputerName", "ComputerName", computer_name),
        _patch("SYSTEM", "/ControlSet001/Services/Tcpip/Parameters", "Hostname", computer_name),
        _patch("SYSTEM", "/ControlSet001/Services/Tcpip/Parameters", "NV Hostname", computer_name),
        _patch("SYSTEM", workstation, "Domain", workgroup),
        _patch("SYSTEM", workstation, "DomainId", "0 0 0 0 0 0"),
        _patch("SYSTEM", workstation, "Account", computer_name),
        _patch("SYSTEM", workstation, "AccountDomainId", account_domain_id),
        _patch("SOFTWARE", "/Microsoft/Windows NT/CurrentVersion/Winlogon", "DefaultDomainName", computer_name),
    ]
    return {
        "computer_name": computer_name,
        "workgroup": workgroup,
        "sid": sid,
        "patches": patches,
    }
