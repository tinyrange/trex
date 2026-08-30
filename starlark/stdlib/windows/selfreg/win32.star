"""Small composable Win32 API models used by registration-time execution."""

load(":facts.star", "guid_bytes")
load(":common.star", "expand_environment")
load("@stdlib//windows:command_line.star", "command_line_arguments")
load("@stdlib//windows:security.star", "legacy_lsa_secret_crypt", "sddl_security_descriptor")

_KERNEL_SIGNATURES = {
    "addrefactctx": 1,
    "changetimerqueuetimer": 4,
    "closehandle": 1,
    "createeventa": 4,
    "createeventw": 4,
    "createsemaphorea": 4,
    "createsemaphorew": 4,
    "createmutexa": 3,
    "createmutexw": 3,
    "createfilea": 7,
    "createfilew": 7,
    "createfilemappinga": 6,
    "createfilemappingw": 6,
    "copyfilea": 3,
    "copyfilew": 3,
    "comparefiletime": 2,
    "comparestringa": 6,
    "comparestringw": 6,
    "createthread": 6,
    "queueuserworkitem": 3,
    "createtimerqueue": 0,
    "createtimerqueuetimer": 7,
    "createdirectorya": 2,
    "createdirectoryw": 2,
    "disablethreadlibrarycalls": 1,
    "dosdatetimetofiletime": 3,
    "duplicatehandle": 7,
    "decodepointer": 1,
    "dbgprint": 1,
    "deletecriticalsection": 1,
    "deletefilea": 1,
    "deletefilew": 1,
    "deletetimerqueue": 1,
    "deletetimerqueueex": 2,
    "deletetimerqueuetimer": 3,
    "delayloadfailurehook": 2,
    "entercriticalsection": 1,
    "encodepointer": 1,
    "exitprocess": 1,
    "exitthread": 1,
    "formatmessagea": 7,
    "formatmessagew": 7,
    "flushfilebuffers": 1,
    "flushviewoffile": 2,
    "filetimetolocalfiletime": 2,
    "filetimetosystemtime": 2,
    "findclose": 1,
    "findclosechangenotification": 1,
    "findfirstfilea": 2,
    "findfirstfilew": 2,
    "findfirstchangenotificationa": 3,
    "findfirstchangenotificationw": 3,
    "findnextfilea": 2,
    "findnextfilew": 2,
    "findnextchangenotification": 1,
    "filetimetodosdatetime": 3,
    "getacp": 0,
    "getcommandlinea": 0,
    "getcommandlinew": 0,
    "getcomputernamea": 2,
    "getcomputernamew": 2,
    "getcomputernameexa": 3,
    "getcomputernameexw": 3,
    "getcpinfo": 2,
    "getcurrentactctx": 1,
    "getdateformata": 6,
    "getdateformatw": 6,
    "getlasterror": 0,
    "getmodulefilenamea": 3,
    "getmodulefilenamew": 3,
    "getmodulehandlea": 1,
    "getmodulehandlew": 1,
    "getmodulehandleexa": 3,
    "getmodulehandleexw": 3,
    "getprivateprofileinta": 4,
    "getprivateprofileintw": 4,
    "getprivateprofilesectiona": 4,
    "getprivateprofilesectionw": 4,
    "getprivateprofilesectionnamesa": 3,
    "getprivateprofilesectionnamesw": 3,
    "getprivateprofilestringa": 6,
    "getprivateprofilestringw": 6,
    "getcurrentprocess": 0,
    "getoemcp": 0,
    "getcurrentprocessid": 0,
    "getcurrentthread": 0,
    "getcurrentthreadid": 0,
    "getthreadpriority": 1,
    "getfileattributesa": 1,
    "getfileattributesw": 1,
    "getfileattributesexa": 3,
    "getfileattributesexw": 3,
    "getfilesize": 2,
    "getfilesizeex": 2,
    "getfiletype": 1,
    "globaladdatoma": 1,
    "globaladdatomw": 1,
    "getexitcodethread": 2,
    "getdrivetypea": 1,
    "getdrivetypew": 1,
    "getdiskfreespacea": 5,
    "getdiskfreespacew": 5,
    "getlocaltime": 1,
    "getlocaleinfoa": 4,
    "getlocaleinfow": 4,
    "getprocaddress": 2,
    "getprocessheap": 0,
    "getprocessversion": 1,
    "getsystemtimeasfiletime": 1,
    "gettempfilenamea": 4,
    "gettempfilenamew": 4,
    "gettemppatha": 2,
    "gettemppathw": 2,
    "getsystemtime": 1,
    "getsystemtimeadjustment": 3,
    "getsysteminfo": 1,
    "isdebuggerpresent": 0,
    "isprocessorfeaturepresent": 1,
    "gettimeformata": 6,
    "gettimeformatw": 6,
    "gettimezoneinformation": 1,
    "getstartupinfoa": 1,
    "getstartupinfow": 1,
    "getstdhandle": 1,
    "getsystempowerstatus": 1,
    "getstringtypea": 5,
    "getstringtypeexa": 5,
    "getstringtypeexw": 5,
    "getstringtypew": 4,
    "getsystemdirectorya": 2,
    "getsystemdirectoryw": 2,
    "getsystemdefaultlangid": 0,
    "getsystemdefaultlcid": 0,
    "getsystemdefaultuilanguage": 0,
    "gettickcount": 0,
    "getversionexa": 1,
    "getversionexw": 1,
    "getversion": 0,
    "getvolumeinformationa": 8,
    "getvolumeinformationw": 8,
    "getuserdefaultlangid": 0,
    "getuserdefaultlcid": 0,
    "getuserdefaultuilanguage": 0,
    "getwindowsdirectorya": 2,
    "getwindowsdirectoryw": 2,
    "globalalloc": 2,
    "globalrealloc": 3,
    "globalfree": 1,
    "globallock": 1,
    "globalmemorystatus": 1,
    "globalmemorystatusex": 1,
    "globalsize": 1,
    "globalunlock": 1,
    "heapalloc": 3,
    "heapcompact": 2,
    "heapcreate": 3,
    "heapdestroy": 1,
    "heapfree": 3,
    "heapsetinformation": 4,
    "heaprealloc": 4,
    "heapsize": 3,
    "heapvalidate": 3,
    "heapwalk": 2,
    "interlockeddecrement": 1,
    "interlockedcompareexchange": 3,
    "interlockedexchange": 2,
    "interlockedexchangeadd": 2,
    "interlockedincrement": 1,
    "localalloc": 2,
    "localrealloc": 3,
    "localfree": 1,
    "localfiletimetofiletime": 2,
    "localsize": 1,
    "loadlibrarya": 1,
    "loadlibraryw": 1,
    "loadlibraryexa": 3,
    "loadlibraryexw": 3,
    "ldrloaddll": 4,
    "mapviewoffile": 5,
    "mapviewoffileex": 6,
    "movefileexa": 3,
    "movefileexw": 3,
    "movefilea": 2,
    "movefilew": 2,
    "removedirectorya": 1,
    "removedirectoryw": 1,
    "ntwritefile": 9,
    "initializecriticalsection": 1,
    "initializecriticalsectionandspincount": 2,
    "isdbcsleadbyte": 1,
    "isbadcodeptr": 1,
    "isbadreadptr": 2,
    "isbadwriteptr": 2,
    "isbadstringptra": 2,
    "isbadstringptrw": 2,
    "iswow64process": 2,
    "leavecriticalsection": 1,
    "freelibrary": 1,
    "lstrcata": 2,
    "lstrcatw": 2,
    "lstrcpya": 2,
    "lstrcpyw": 2,
    "lstrcpyna": 3,
    "lstrcpynw": 3,
    "lstrlena": 1,
    "lstrlenw": 1,
    "lcmapstringa": 6,
    "lcmapstringw": 6,
    "lstrcmpa": 2,
    "lstrcmpw": 2,
    "lstrcmpia": 2,
    "lstrcmpiw": 2,
    "multibytetowidechar": 6,
    # REGHANDLE consumes two 32-bit stack slots on x86.
    "etweventenabled": 3,
    "etweventregister": 4,
    "etweventunregister": 2,
    "etweventwrite": 5,
    "ntcreateport": 5,
    "ntcreateevent": 5,
    "ntclose": 1,
    "ntallocatelocallyuniqueid": 1,
    "ntopenevent": 3,
    "ntqueryinformationprocess": 5,
    "ntqueryinformationthread": 5,
    "ntquerysysteminformation": 4,
    "ntquerysystemtime": 1,
    "ntrequestwaitreplyport": 3,
    "ntsetevent": 2,
    "ntsetinformationthread": 4,
    "ntwaitforsingleobject": 3,
    "zwqueryinformationprocess": 5,
    "zwquerysysteminformation": 4,
    "rtlintegertounicodestring": 3,
    "rtlinitstring": 2,
    "rtlcopyunicodestring": 2,
    "rtlntstatustodoserror": 1,
    "openmutexa": 3,
    "openmutexw": 3,
    "openfilemappinga": 3,
    "openfilemappingw": 3,
    "openprocess": 3,
    "openthread": 3,
    "openeventa": 3,
    "openeventw": 3,
    "outputdebugstringa": 1,
    "outputdebugstringw": 1,
    "queryperformancecounter": 1,
    "queryperformancefrequency": 1,
    "readfile": 5,
    "reinitializecriticalsection": 1,
    "releaseactctx": 1,
    "resolvedelayloadedapi": 6,
    "setlasterror": 1,
    "setunhandledexceptionfilter": 1,
    "setevent": 1,
    "setconsolectrlhandler": 2,
    "seterrormode": 1,
    "sethandlecount": 1,
    "setprocessshutdownparameters": 2,
    "setthreadpriority": 2,
    "setsystemtimeadjustment": 2,
    "setfileattributesa": 2,
    "setfileattributesw": 2,
    "setendoffile": 1,
    "setfilepointer": 4,
    "setfilepointerex": 5,
    "setfiletime": 4,
    "systemtimetofiletime": 2,
    "sleep": 1,
    "switchtothread": 0,
    "terminateprocess": 2,
    "thunkconnect32": 6,
    "tlsalloc": 0,
    "tlsfree": 1,
    "tlsgetvalue": 1,
    "tlssetvalue": 2,
    "unhandledexceptionfilter": 1,
    "unregisterwait": 1,
    "unregisterwaitex": 2,
    "unmapviewoffile": 1,
    "virtualalloc": 4,
    "virtualfree": 3,
    "virtualprotect": 4,
    "virtualquery": 3,
    "versetconditionmask": 4,
    "verifyversioninfoa": 4,
    "verifyversioninfow": 4,
    "resetevent": 1,
    "resumethread": 1,
    "registerwaitforsingleobject": 6,
    "searchpatha": 6,
    "searchpathw": 6,
    "releasemutex": 1,
    "releasesemaphore": 3,
    "tryentercriticalsection": 1,
    "waitforsingleobject": 2,
    "waitforsingleobjectex": 3,
    "waitformultipleobjects": 4,
    "waitformultipleobjectsex": 5,
    "widechartomultibyte": 8,
    "writefile": 5,
    "writeprivateprofilestringa": 4,
    "writeprivateprofilestringw": 4,
    "writeprivateprofilesectiona": 3,
    "writeprivateprofilesectionw": 3,
    "rtldeletecriticalsection": 1,
    "rtldeleteresource": 1,
    "rtldestroyheap": 1,
    "rtlentercriticalsection": 1,
    "rtlacquireresourceexclusive": 2,
    "rtlacquireresourceshared": 2,
    "rtlallocateheap": 3,
    "rtlcreateheap": 6,
    "rtlfreeheap": 3,
    "rtlgetntproducttype": 1,
    "rtlgetntversionnumbers": 3,
    "rtlimagentheader": 1,
    "rtlansistringtounicodestring": 3,
    "rtlappendunicodestringtostring": 2,
    "rtlappendunicodetostring": 2,
    "rtlfreeansistring": 1,
    "rtlfreeunicodestring": 1,
    "rtlinitansistring": 2,
    "rtlinitunicodestring": 2,
    "rtlunicodestringtoansistring": 3,
    "rtlvalidateprocessheaps": 0,
    "rtlinitializecriticalsection": 1,
    "rtlinitializecriticalsectionandspincount": 2,
    "rtlinitializeresource": 1,
    "rtlleavecriticalsection": 1,
    "rtlreallocateheap": 4,
    "rtlreleaseresource": 1,
    "rtlsizeheap": 3,
    "rtltryentercriticalsection": 1,
    "rtlfillmemory": 3,
    "rtlmovememory": 3,
    "rtlzeromemory": 2,
}

_OLE_SIGNATURES = {
    "clsidfromstring": 2,
    "cocreateinstance": 5,
    "cocreateinstanceex": 6,
    "cocreatefreethreadedmarshaler": 2,
    "cocreateguid": 1,
    "codisconnectcontext": 1,
    "cogetcallcontext": 2,
    "cogetclassobject": 5,
    "cogetinterfaceandreleasestream": 3,
    "cogetmalloc": 2,
    "cogetmarshalsizemax": 6,
    "cogetpsclsid": 2,
    "coimpersonateclient": 0,
    "coinitialize": 1,
    "coinitializeex": 2,
    "coinitializesecurity": 9,
    "comarshalinterthreadinterfaceinstream": 3,
    "oleinitialize": 1,
    "oleuninitialize": 0,
    "iidfromstring": 2,
    "coregisterclassobject": 5,
    "coregisterpsclsid": 2,
    "coresumeclassobjects": 0,
    "corevokeclassobject": 1,
    "coqueryproxyblanket": 8,
    "cosetproxyblanket": 8,
    "cosuspendclassobjects": 0,
    "coswitchcallcontext": 2,
    "comarshalinterface": 6,
    "coreleasemarshaldata": 1,
    "coreverttoself": 0,
    "couninitialize": 0,
    "cotaskmemalloc": 1,
    "cotaskmemfree": 1,
    "counmarshalinterface": 3,
    "createstreamonhglobal": 3,
    "dcomchannelsethresult": 2,
    "freepropvariantarray": 2,
    "gethglobalfromstream": 2,
    "propvariantclear": 1,
    "propvariantcopy": 2,
    "stringfromclsid": 2,
    "stringfromiid": 2,
    "stringfromguid2": 3,
}

_OLEAUT_SIGNATURES = {
    2: 1, 3: 2, 4: 2, 5: 3, 6: 1, 7: 1, 8: 1, 9: 1, 10: 2, 12: 4,
    15: 3, 16: 1, 17: 1, 18: 1, 19: 3, 20: 3, 23: 2, 24: 1,
    25: 3, 26: 3, 27: 2, 38: 1, 39: 1, 40: 2, 77: 2,
    147: 5, 149: 1, 150: 2, 161: 2, 162: 5, 163: 3, 183: 3, 184: 2,
    186: 5, 200: 2, 201: 2,
    411: 3,
}

def _encoded(value, wide, nul = True):
    return binary.encode(value, encoding = "utf16le" if wide else "ascii", nul = nul)

def _is_leap_year(year):
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)

def _filetime_ticks(year, month, day, hour, minute, second, millisecond):
    if year < 1601 or month < 1 or month > 12 or hour > 23 or minute > 59 or second > 59 or millisecond > 999:
        return None
    month_days = [31, 29 if _is_leap_year(year) else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    if day < 1 or day > month_days[month - 1]:
        return None
    before = year - 1
    epoch = 1600
    days = 365 * before + before // 4 - before // 100 + before // 400
    days -= 365 * epoch + epoch // 4 - epoch // 100 + epoch // 400
    for index in range(month - 1):
        days += month_days[index]
    days += day - 1
    ticks = (((days * 24 + hour) * 60 + minute) * 60 + second) * 10000000 + millisecond * 10000
    return ticks if ticks <= 0xffffffffffffffff else None

def _filetime_fields(ticks):
    if ticks < 0 or ticks > 0xffffffffffffffff:
        return None
    milliseconds = (ticks // 10000) % 1000
    total_seconds = ticks // 10000000
    second = total_seconds % 60
    total_minutes = total_seconds // 60
    minute = total_minutes % 60
    total_hours = total_minutes // 60
    hour = total_hours % 24
    days = total_hours // 24
    weekday = (days + 1) % 7  # 1601-01-01 was Monday.

    year = 1601 + (days // 146097) * 400
    days %= 146097
    while True:
        year_days = 366 if _is_leap_year(year) else 365
        if days < year_days:
            break
        days -= year_days
        year += 1
    month_days = [31, 29 if _is_leap_year(year) else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    month = 1
    while days >= month_days[month - 1]:
        days -= month_days[month - 1]
        month += 1
    return [year, month, weekday, days + 1, hour, minute, second, milliseconds]

def _deterministic_guid(sequence):
    builder = binary.builder(capacity = 16)
    builder.u32le(0x54525800 | (sequence & 0xff))
    builder.u16le((sequence >> 8) & 0xffff)
    builder.u16le(0x4000 | ((sequence >> 24) & 0x0fff))
    builder.u8(0x80)
    builder.u8(0x54)
    builder.u32le(sequence & 0xffffffff)
    builder.u16le(0x5854)
    return builder.bytes()

def _write_string(machine, address, value, wide, capacity = 0):
    data = _encoded(value, wide)
    if capacity:
        data = data[:capacity * (2 if wide else 1)]
    machine.write(address, data)
    return len(value)

def _execution_thread_state(reason):
    """Maps an execution stop to its cooperative scheduler state."""
    if reason == "return":
        return "terminated"
    if reason == "wait":
        return "waiting"
    if reason == "budget":
        return "runnable"
    return "stopped"

def _system_power_status():
    """Returns a deterministic AC-powered, battery-free status structure."""
    status = binary.builder(capacity = 12)
    status.u8(1)      # AC_LINE_ONLINE
    status.u8(0x80)   # BATTERY_FLAG_NO_BATTERY
    status.u8(0xff)   # BATTERY_PERCENTAGE_UNKNOWN
    status.u8(0)
    status.u32le(0xffffffff)
    status.u32le(0xffffffff)
    return status.bytes()

_VERSION_CONDITION_SHIFTS = {
    0x00000001: 0,   # VER_MINORVERSION
    0x00000002: 3,   # VER_MAJORVERSION
    0x00000004: 6,   # VER_BUILDNUMBER
    0x00000008: 9,   # VER_PLATFORMID
    0x00000010: 12,  # VER_SERVICEPACKMINOR
    0x00000020: 15,  # VER_SERVICEPACKMAJOR
    0x00000040: 18,  # VER_SUITENAME
    0x00000080: 21,  # VER_PRODUCT_TYPE
}

def _version_condition_mask(mask, type_mask, condition):
    """Applies one VerSetConditionMask operation to a 64-bit mask."""
    for version_type, shift in _VERSION_CONDITION_SHIFTS.items():
        if type_mask & version_type:
            mask = (mask & ~(7 << shift)) | ((condition & 7) << shift)
    return mask

def _version_condition_satisfied(actual, requested, condition):
    if condition == 1:
        return actual == requested
    if condition == 2:
        return actual > requested
    if condition == 3:
        return actual >= requested
    if condition == 4:
        return actual < requested
    if condition == 5:
        return actual <= requested
    if condition == 6:
        return actual & requested == requested
    if condition == 7:
        return bool(actual & requested)
    return False

def _tracked_allocate(machine, allocations, size, name):
    address = machine.allocate(size = max(1, size), name = name)
    allocations[address] = size
    return address

def _tracked_reallocate(machine, allocations, address, size, name):
    if not address:
        return _tracked_allocate(machine, allocations, size, name) if size else 0
    previous = allocations.get(address)
    if previous == None:
        return 0
    if not size:
        allocations.pop(address)
        machine.free(address)
        return 0
    replacement = _tracked_allocate(machine, allocations, size, name)
    copied = min(previous, size)
    if copied:
        machine.write(replacement, machine.read(address, copied))
    allocations.pop(address)
    machine.free(address)
    return replacement

def _scan_integer(source, format):
    """Parses one scanf integer conversion and returns its value and width."""
    if not format.startswith("%") or len(format) < 2:
        return None
    index = 1
    field_width = 0
    while index < len(format) and format[index] >= "0" and format[index] <= "9":
        field_width = field_width * 10 + int(format[index])
        index += 1
    length = ""
    for candidate in ["I64", "I32", "ll", "l", "h"]:
        if format[index:].startswith(candidate):
            length = candidate
            index += len(candidate)
            break
    if index + 1 != len(format) or "diuoxX".find(format[index]) < 0:
        return None
    conversion = format[index]
    text = source.lstrip()
    if field_width:
        text = text[:field_width]
    negative = False
    if text.startswith("+") or text.startswith("-"):
        negative = text.startswith("-")
        text = text[1:]
    base = 10
    if "xX".find(conversion) >= 0:
        base = 16
    elif conversion == "o":
        base = 8
    elif conversion == "i":
        if text.lower().startswith("0x"):
            base = 16
        elif text.startswith("0"):
            base = 8
    if base == 16 and text.lower().startswith("0x"):
        text = text[2:]
    alphabet = "0123456789abcdef"
    value = 0
    digits = 0
    lowered = text.lower()
    for index in range(len(lowered)):
        character = lowered[index]
        digit = alphabet.find(character)
        if digit < 0 or digit >= base:
            break
        value = value * base + digit
        digits += 1
    if digits == 0:
        return None
    if negative:
        value = -value
    bits = 64 if length in ["I64", "ll"] else (16 if length == "h" else 32)
    return {"value": value & ((1 << bits) - 1), "bits": bits}

def _scan_float(source, format):
    """Parses one decimal scanf floating conversion and its destination width."""
    if not format.startswith("%") or len(format) < 2:
        return None
    index = 1
    field_width = 0
    while index < len(format) and format[index] >= "0" and format[index] <= "9":
        field_width = field_width * 10 + int(format[index])
        index += 1
    length = ""
    if index < len(format) and format[index] in ["l", "L"]:
        length = format[index]
        index += 1
    if index + 1 != len(format) or format[index] not in "eEfFgG":
        return None

    text = source.lstrip()
    if field_width:
        text = text[:field_width]
    cursor = 0
    if cursor < len(text) and text[cursor] in "+-":
        cursor += 1
    digits = 0
    while cursor < len(text) and text[cursor] >= "0" and text[cursor] <= "9":
        cursor += 1
        digits += 1
    if cursor < len(text) and text[cursor] == ".":
        cursor += 1
        while cursor < len(text) and text[cursor] >= "0" and text[cursor] <= "9":
            cursor += 1
            digits += 1
    if digits == 0:
        return None
    exponent = cursor
    if cursor < len(text) and text[cursor] in "eE":
        cursor += 1
        if cursor < len(text) and text[cursor] in "+-":
            cursor += 1
        exponent_digits = cursor
        while cursor < len(text) and text[cursor] >= "0" and text[cursor] <= "9":
            cursor += 1
        if cursor == exponent_digits:
            cursor = exponent
    return {
        "value": float(text[:cursor]),
        "bits": 64 if length in ["l", "L"] else 32,
        "floating": True,
    }

def _parse_c_integer(source, base):
    """Parses the integer prefix accepted by the CRT strtol family."""
    start = 0
    while start < len(source) and source[start] in " \t\r\n\v\f":
        start += 1
    index = start
    negative = False
    if index < len(source) and source[index] in "+-":
        negative = source[index] == "-"
        index += 1
    if base == 0:
        if source[index:index + 2].lower() == "0x":
            base = 16
            index += 2
        elif index < len(source) and source[index] == "0":
            base = 8
        else:
            base = 10
    elif base == 16 and source[index:index + 2].lower() == "0x":
        index += 2
    if base < 2 or base > 36:
        return {"value": 0, "consumed": 0}
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    value = 0
    count = 0
    while index < len(source):
        digit = digits.find(source[index].lower())
        if digit < 0 or digit >= base:
            break
        value = value * base + digit
        count += 1
        index += 1
    if count == 0:
        return {"value": 0, "consumed": 0}
    return {"value": -value if negative else value, "consumed": index}

def _radix_text(value, radix):
    if radix < 2 or radix > 36:
        return ""
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    if value == 0:
        return "0"
    output = ""
    while value:
        output = alphabet[value % radix] + output
        value //= radix
    return output

def _module_windows_directory(module_path):
    parts = module_path.replace("/", "\\").split("\\")
    for index in range(len(parts)):
        if parts[index].lower() in ["system", "system32"]:
            return "\\".join(parts[:index])
    return "\\".join(parts[:-1])

def _stub_plugin(name, modules, signatures, callback):
    def install(machine):
        for imported in machine.imports:
            function = imported.name.lower()
            if imported.module.lower() in modules and function in signatures:
                machine.hook(callback, address = imported.address, argc = signatures[function])
    return emulator.plugin(install, name = name)

def _event_log_provider_module(name):
    normalized = name.replace("/", "\\").split("\\")[-1].lower()
    return normalized == "advapi32.dll" or normalized.startswith("api-ms-win-event") or normalized.startswith("ext-ms-win-event")

def event_log_plugin():
    """Models registration-time Event Log and disabled ETW providers."""
    state = {"next_handle": 0x50000, "sources": {}, "events": [], "trace_providers": {}, "trace_messages": []}
    signatures = {
        "deregistereventsource": 1,
        "gettraceenableflags": 2,
        "gettraceenablelevel": 2,
        "gettraceloggerhandle": 1,
        "registereventsourcea": 2,
        "registereventsourcew": 2,
        "registertraceguidsa": 8,
        "registertraceguidsw": 8,
        "reporteventa": 9,
        "reporteventw": 9,
        "tracemessage": 5,
        "unregistertraceguids": 2,
    }

    def callback(event):
        name = event.name.lower()
        args = event.args
        machine = event.machine
        wide = name.endswith("w")
        encoding = "utf16le" if wide else "ascii"
        if name.startswith("registertraceguids"):
            if not args[7] or args[3] > 65536:
                return 87  # ERROR_INVALID_PARAMETER
            handle = state["next_handle"]
            state["next_handle"] = handle + 1
            state["trace_providers"][handle] = {
                "callback": args[0],
                "context": args[1],
                "control_guid": _guid_text(machine, args[2]) if args[2] else "",
                "guid_count": args[3],
                "mof_image": machine.read_cstring(args[5], encoding = encoding) if args[5] else "",
                "mof_resource": machine.read_cstring(args[6], encoding = encoding) if args[6] else "",
            }
            value = binary.builder(capacity = 8)
            value.u64le(handle)
            machine.write(args[7], value.bytes())
            return 0
        if name == "unregistertraceguids":
            handle = args[0] | (args[1] << 32)
            if handle not in state["trace_providers"]:
                return 6  # ERROR_INVALID_HANDLE
            state["trace_providers"].pop(handle)
            return 0
        if name in ["gettraceenableflags", "gettraceenablelevel", "gettraceloggerhandle"]:
            return 0
        if name == "tracemessage":
            state["trace_messages"].append({
                "logger": args[0] | (args[1] << 32),
                "flags": args[2],
            })
            return 0
        if name.startswith("registereventsource"):
            handle = state["next_handle"]
            state["next_handle"] = handle + 1
            state["sources"][handle] = {
                "server": machine.read_cstring(args[0], encoding = encoding) if args[0] else "",
                "source": machine.read_cstring(args[1], encoding = encoding) if args[1] else "",
            }
            return handle
        if name == "deregistereventsource":
            if args[0] not in state["sources"]:
                return 0
            state["sources"].pop(args[0])
            return 1
        if name.startswith("reportevent"):
            if args[0] not in state["sources"] or args[5] > 256 or args[6] > (1 << 20):
                return 0
            strings = []
            for index in range(args[5]):
                pointer = machine.read_u32le(args[7] + index * 4)
                strings.append(machine.read_cstring(pointer, encoding = encoding) if pointer else "")
            state["events"].append({
                "source": state["sources"][args[0]],
                "type": args[1],
                "category": args[2],
                "id": args[3],
                "strings": strings,
                "data": machine.read(args[8], args[6]) if args[8] and args[6] else b"",
            })
            return 1
        return 0

    def install(machine):
        for name, argc in signatures.items():
            machine.provide_export(
                callback,
                module = "advapi32.dll",
                name = name,
                argc = argc,
                convention = "cdecl" if name == "tracemessage" else "stdcall",
            )
        for imported in machine.imports:
            name = imported.name.lower()
            if _event_log_provider_module(imported.module) and name in signatures:
                machine.hook(
                    callback,
                    address = imported.address,
                    argc = signatures[name],
                    convention = "cdecl" if name == "tracemessage" else "stdcall",
                )
    return emulator.plugin(install, name = "windows.event_log", state = state)

def environment_plugin(values = {}, system_time = 946684800):
    """Models a mutable Win32 environment.

    `system_time` is a portable Unix timestamp used to initialize the
    KUSER_SHARED_DATA wall clock visible to native code.
    """
    state = {"values": {}, "peb": 0, "parameters": 0}
    for name, value in values.items():
        state["values"][name.lower()] = (name, str(value))
    fields = clock.utc(system_time)
    system_time_ticks = _filetime_ticks(
        fields["year"], fields["month"], fields["day"],
        fields["hour"], fields["minute"], fields["second"], fields["millisecond"],
    )

    def get(name):
        entry = state["values"].get(name.lower())
        return None if entry == None else entry[1]

    def set(name, value):
        normalized = name.lower()
        if value == None:
            state["values"].pop(normalized, None)
        else:
            state["values"][normalized] = (name, value)

    def expand(value):
        return expand_environment(value, {entry[0]: entry[1] for entry in state["values"].values()})

    def unicode_string(machine, address):
        record = binary.cursor(machine.read(address, 8))
        length = record.u16le()
        maximum = record.u16le()
        buffer = record.u32le()
        value = binary.text(machine.read(buffer, length), encoding = "utf16le") if buffer and length else ""
        return value, maximum, buffer

    def write_unicode_string(machine, address, value):
        unused, maximum, buffer = unicode_string(machine, address)
        encoded = binary.encode(value, encoding = "utf16le")
        if len(encoded) > maximum:
            return False, len(encoded)
        if encoded:
            machine.write(buffer, encoded)
        machine.write_u16le(address, len(encoded))
        return True, len(encoded)

    def environment_block(machine, wide = True):
        rows = []
        for unused, entry in sorted(state["values"].items()):
            rows.append(entry[0] + "=" + entry[1])
        data = binary.encode("\x00".join(rows) + "\x00\x00", encoding = "utf16le" if wide else "ascii")
        return machine.allocate(size = len(data), value = data, name = "process.environment")

    def callback(event):
        name = event.name.lower()
        args = event.args
        machine = event.machine
        wide = name.endswith("w")
        encoding = "utf16le" if wide else "ascii"
        if name in ["getenvironmentvariablea", "getenvironmentvariablew"]:
            variable = machine.read_cstring(args[0], encoding = encoding)
            value = get(variable)
            if value == None:
                return 0
            required = len(value) + 1
            if args[2] < required:
                return required
            _write_string(machine, args[1], value, wide, args[2])
            return len(value)
        if name in ["setenvironmentvariablea", "setenvironmentvariablew"]:
            variable = machine.read_cstring(args[0], encoding = encoding)
            value = machine.read_cstring(args[1], encoding = encoding) if args[1] else None
            set(variable, value)
            return 1
        if name in ["expandenvironmentstringsa", "expandenvironmentstringsw"]:
            value = expand(machine.read_cstring(args[0], encoding = encoding))
            required = len(value) + 1
            if args[1] and args[2]:
                _write_string(machine, args[1], value, wide, args[2])
            return required
        if name in ["getenvironmentstringsa", "getenvironmentstringsw"]:
            return environment_block(machine, wide)
        if name in ["freeenvironmentstringsa", "freeenvironmentstringsw"]:
            return 1
        if name == "rtlcreateenvironment":
            machine.write_u32le(args[1], environment_block(machine))
            return 0
        if name in ["rtlsetcurrentenvironment", "rtldestroyenvironment"]:
            if name == "rtlsetcurrentenvironment" and args[1]:
                machine.write_u32le(args[1], 0)
            return 0
        if name == "rtlexpandenvironmentstrings_u":
            source, unused, unused = unicode_string(machine, args[1])
            value = expand(source)
            written, required = write_unicode_string(machine, args[2], value)
            if args[3]:
                machine.write_u32le(args[3], required)
            return 0 if written else 0xc0000023
        if name == "rtlqueryenvironmentvariable_u":
            variable, unused, unused = unicode_string(machine, args[1])
            value = get(variable)
            if value == None:
                return 0xc0000100  # STATUS_VARIABLE_NOT_FOUND
            written, unused = write_unicode_string(machine, args[2], value)
            return 0 if written else 0xc0000023
        if name == "rtlsetenvironmentvariable":
            variable, unused, unused = unicode_string(machine, args[1])
            value = unicode_string(machine, args[2])[0] if args[2] else None
            set(variable, value)
            return 0
        return 0

    def install(machine):
        environment = environment_block(machine)
        shared_data = machine.allocate(
            address = 0x7ffe0000,
            size = 0x1000,
            alignment = 0x1000,
            name = "KUSER_SHARED_DATA",
            readable = True,
            writable = True,
        )
        parameters = machine.allocate(size = 0x100, name = "RTL_USER_PROCESS_PARAMETERS")
        peb = machine.allocate(size = 0x100, name = "PEB")
        state["parameters"] = parameters
        state["peb"] = peb
        state["shared_data"] = shared_data
        # KSYSTEM_TIME uses a high-low-high sequence so readers can detect a
        # concurrent update without a syscall. Static emulation publishes one
        # coherent value at the native Windows 0x14 SystemTime offset.
        machine.write_u32le(shared_data + 0x14, system_time_ticks & 0xffffffff)
        machine.write_u32le(shared_data + 0x18, system_time_ticks >> 32)
        machine.write_u32le(shared_data + 0x1c, system_time_ticks >> 32)
        machine.protect(address = shared_data, size = 0x1000, readable = True, writable = False, executable = False)
        machine.write_u32le(parameters + 0x48, environment)
        machine.write_u32le(peb + 0x10, parameters)
        machine.write_u32le(peb + 0x18, 1)
        teb = machine.segment_base("fs")
        if teb:
            machine.write_u32le(teb + 0x30, peb)
        signatures = {
            "getenvironmentvariablea": 3, "getenvironmentvariablew": 3,
            "setenvironmentvariablea": 2, "setenvironmentvariablew": 2,
            "expandenvironmentstringsa": 3, "expandenvironmentstringsw": 3,
            "getenvironmentstringsa": 0, "getenvironmentstringsw": 0,
            "freeenvironmentstringsa": 1, "freeenvironmentstringsw": 1,
            "rtlcreateenvironment": 2, "rtlsetcurrentenvironment": 2,
            "rtldestroyenvironment": 1, "rtlexpandenvironmentstrings_u": 4,
            "rtlqueryenvironmentvariable_u": 3, "rtlsetenvironmentvariable": 3,
        }
        for function, argc in signatures.items():
            module = "ntdll.dll" if function.startswith("rtl") else "kernel32.dll"
            machine.provide_export(callback, module = module, name = function, argc = argc)
        for imported in machine.imports:
            name = imported.name.lower()
            if _kernel_provider_module(imported.module) and name in signatures:
                machine.hook(callback, address = imported.address, argc = signatures[name])
    return emulator.plugin(install, name = "windows.environment", state = state)

def _normalize_virtual_path(path):
    normalized = path.replace("/", "\\")
    unc = normalized.startswith("\\\\")
    body = normalized[2:] if unc else normalized
    while "\\\\" in body:
        body = body.replace("\\\\", "\\")
    return (("\\\\" if unc else "") + body).rstrip("\\").lower()

def _virtual_path_access(paths, path, mode):
    """Checks CRT read/write access against a guest-backed path table."""
    if mode & ~6:
        return False
    entry = paths.get(_normalize_virtual_path(path))
    if entry == None:
        return False
    if mode & 4 and not entry.get("readable", True):
        return False
    if mode & 2 and not entry.get("writable", True):
        return False
    return True

def _wildcard_match(pattern, value):
    """Matches one case-insensitive Win32-style filename pattern."""
    pattern = pattern.lower()
    value = value.lower()
    # FindFirstFile retains the DOS convention that *.* enumerates every
    # directory entry, including names without a dot.
    if pattern == "*.*":
        pattern = "*"
    current = [True] + [False] * len(value)
    for pattern_index in range(len(pattern)):
        token = pattern[pattern_index]
        following = [False] * (len(value) + 1)
        if token == "*":
            following[0] = current[0]
            for index in range(1, len(value) + 1):
                following[index] = current[index] or following[index - 1]
        else:
            for index in range(1, len(value) + 1):
                following[index] = current[index - 1] and (token == "?" or token == value[index - 1])
        current = following
    return current[-1]

def _virtual_file_entries(files, maximum_source_file_size, directories = []):
    entries = {}
    for supplied_path, source in files.items():
        path = _normalize_virtual_path(supplied_path)
        if not path or path in entries:
            fail("invalid or duplicate virtual file path: " + supplied_path)
        view = binary.view(source)
        if view.size > maximum_source_file_size:
            fail("virtual file exceeds the maximum modeled file size: " + supplied_path)
        entries[path] = {
            "source": source,
            "size": view.size,
            "directory": False,
            "initial": True,
            "dirty": False,
        }
        parts = path.split("\\")
        for count in range(1, len(parts)):
            parent = "\\".join(parts[:count])
            if parent and parent not in entries:
                entries[parent] = {"directory": True, "initial": True, "dirty": False}
    for supplied_path in directories:
        path = _normalize_virtual_path(supplied_path)
        if not path:
            fail("invalid virtual directory path: " + supplied_path)
        existing = entries.get(path)
        if existing != None and not existing.get("directory", False):
            fail("virtual directory conflicts with a file: " + supplied_path)
        parts = path.split("\\")
        for count in range(1, len(parts) + 1):
            parent = "\\".join(parts[:count])
            if parent and parent not in entries:
                entries[parent] = {"directory": True, "initial": True, "dirty": False}
    return entries

def virtual_file_entries(files):
    """Prepares immutable guest file metadata for repeated process models."""
    return _virtual_file_entries(files, 512 << 20)

def _profile_sections(data):
    """Parses the section and key/value subset shared by INI and setup INF files."""
    if data[:2] == b"\xff\xfe":
        text = binary.text(data[2:], encoding = "utf16le")
    else:
        text = binary.text(data, encoding = "ascii")
    order = []
    sections = {}
    current = None
    for raw_line in text.replace("\r", "").split("\n"):
        line = raw_line.strip()
        if not line or line.startswith(";") or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1].strip()
            identity = name.lower()
            if identity not in sections:
                order.append(name)
                sections[identity] = {"name": name, "items": [], "values": {}}
            current = sections[identity]
            continue
        if current == None:
            continue
        separator = line.find("=")
        key = line[:separator].strip() if separator >= 0 else line
        value = line[separator + 1:].strip() if separator >= 0 else ""
        current["items"].append({"key": key, "value": value, "line": key + "=" + value if separator >= 0 else key})
        current["values"][key.lower()] = value
    return {"order": order, "sections": sections}

def _kernel_provider_module(name):
    """Reports whether an import module resolves through Kernel32/NTDLL.

    API-set contracts deliberately describe an API surface rather than a
    concrete DLL.  The semantic runtime already owns the selected function by
    signature, so core and extension contracts must resolve through the same
    provider as their legacy Kernel32/NTDLL imports.
    """
    normalized = name.replace("/", "\\").split("\\")[-1].lower()
    return normalized in ["kernel32.dll", "ntdll.dll"] or normalized.startswith("api-ms-win-core-") or normalized.startswith("ext-ms-win-")

def kernel32_plugin(module_path = "", version = {}, environment = {}, volumes = {}, virtual_modules = [], files = {}, directories = [], prepared_file_entries = None, on_thread_create = None, on_module_load = None, command_line = "regsvr32.exe", thread_instruction_limit = 100000, on_system_query = None, system_query_provider = None, system_time = 946684800):
    """Models deterministic allocation, strings, paths, files, and OS facts.

    `files` maps guest paths to bytes or trex files. They are made
    available directly to target file APIs without host filesystem staging.
    `directories` supplies empty or otherwise implicit guest directories.
    `on_thread_create(event, thread)` may schedule the captured start routine
    using emulator control APIs; no host thread is created implicitly.
    `on_system_query(machine, query)` may inspect one live, bounded diagnostic
    query and return a compact observation for the plugin state.
    `system_query_provider(machine, query)` may return a response containing
    `status`, `required_length`, optional `short_status`, and optional `data`.
    Returning `None` delegates to the built-in deterministic system facts.
    `system_time` is a portable Unix timestamp used by the Windows wall-clock
    APIs. Its default preserves the historic deterministic 2000-01-01 value.
    """
    normalized_module = module_path.replace("/", "\\")
    windows_directory = _module_windows_directory(normalized_module)
    version_major = int(version.get("major", 5))
    version_minor = int(version.get("minor", 1))
    version_build = int(version.get("build", 2600))
    service_pack_major = int(version.get("service_pack_major", 3))
    service_pack_minor = int(version.get("service_pack_minor", 0))
    service_pack = version.get("service_pack", "Service Pack 3")
    platform_id = int(version.get("platform_id", 2))
    system_directory = windows_directory + ("\\system" if platform_id == 1 else "\\system32")
    product_type = version.get("product_type", "WinNT").lower()
    product_type_number = 1 if product_type == "winnt" else (2 if product_type == "lanmannt" else 3)
    suite_mask = int(version.get("suite_mask", 0))
    system_time_fields = clock.utc(system_time)
    system_time_ticks = _filetime_ticks(
        system_time_fields["year"],
        system_time_fields["month"],
        system_time_fields["day"],
        system_time_fields["hour"],
        system_time_fields["minute"],
        system_time_fields["second"],
        system_time_fields["millisecond"],
    )
    system_time_structure = [
        system_time_fields["year"],
        system_time_fields["month"],
        system_time_fields["weekday"],
        system_time_fields["day"],
        system_time_fields["hour"],
        system_time_fields["minute"],
        system_time_fields["second"],
        system_time_fields["millisecond"],
    ]
    processor_features = {int(feature): True for feature in version.get("processor_features", [2, 3, 6, 8])}
    computer_name = environment.get("COMPUTERNAME", environment.get("ComputerName", "TREX"))
    dns_host_name = environment.get("DNSHOSTNAME", environment.get("DnsHostName", computer_name))
    dns_domain = environment.get("USERDNSDOMAIN", environment.get("DNSDOMAIN", environment.get("DnsDomain", "")))
    volume_facts = {name[:2].upper(): dict(value) for name, value in volumes.items()}
    maximum_file_size = 16 << 20
    maximum_source_file_size = 512 << 20
    paths = _virtual_file_entries(files, maximum_source_file_size, directories = directories) if prepared_file_entries == None else {
        path: dict(entry)
        for path, entry in prepared_file_entries.items()
    }
    if thread_instruction_limit < 1 or thread_instruction_limit > 10000000:
        fail("kernel thread instruction limit must be between 1 and 10000000")
    state = {"last_error": 0, "modules": {}, "handles": {}, "next_handle": 0x40000, "next_luid": 0x1000, "next_etw_handle": 1, "main": 0, "current_actctx": 0, "actctx_refs": 0, "tls": {}, "next_tls": 0, "next_temp": 1, "next_thread_id": 16, "threads": [], "executions": {}, "current_thread": None, "thread_priorities": {8: 0}, "thread_io_priorities": {8: 2}, "thread_page_priorities": {8: 5}, "timer_callbacks": [], "tick_count": 0, "time_adjustment": 156250, "time_increment": 156250, "time_adjustment_disabled": False, "paths": paths, "named_mappings": {}, "views": {}, "file_queries": [], "module_queries": [], "procedure_queries": [], "process_queries": [], "thread_queries": [], "system_queries": [], "profile_queries": [], "debug_output": [], "heaps": {1: True}, "allocations": {}, "resources": {}, "critical_sections": {}, "global_allocations": {}, "local_allocations": {}, "virtual_allocations": {}, "virtual_protections": {}, "standard_handles": {}, "command_line": command_line, "command_lines": {}, "process_exit_code": None, "process_userdata": 0, "unhandled_exception_filter": 0}

    def entry_data(entry):
        if entry == None or entry.get("directory", False):
            return b""
        if "data" not in entry:
            view = binary.view(entry["source"])
            entry["data"] = view.slice(0, view.size).bytes()
            entry["size"] = len(entry["data"])
        return entry["data"]

    def file_data(path):
        return entry_data(state["paths"].get(path))

    state["file_data"] = file_data

    def create_handle(kind, value = {}):
        handle = state["next_handle"]
        state["next_handle"] = handle + 1
        state["handles"][handle] = {"kind": kind, "value": value}
        return handle

    def file_path(machine, address, wide):
        return _normalize_virtual_path(machine.read_cstring(address, encoding = "utf16le" if wide else "ascii"))

    def file_handle(handle):
        entry = state["handles"].get(handle)
        if type(entry) != "dict" or entry.get("kind") != "file":
            return None
        return entry["value"]

    def profile(machine, address, wide):
        supplied = machine.read_cstring(address, encoding = "utf16le" if wide else "ascii") if address else ""
        supplied = expand_environment(supplied, environment)
        path = _normalize_virtual_path(supplied)
        if "\\" not in path:
            path = _normalize_virtual_path(windows_directory + "\\" + path)
        entry = state["paths"].get(path)
        if entry == None or entry.get("directory", False):
            return path, {"order": [], "sections": {}}
        return path, _profile_sections(entry_data(entry))

    def write_profile_list(machine, address, values, wide, capacity):
        if capacity <= 0 or not address:
            return 0
        if not values:
            value = "\x00\x00"[:capacity]
            machine.write(address, binary.encode(value, encoding = "utf16le" if wide else "ascii"))
            return 0
        value = "\x00".join(values) + "\x00\x00"
        if len(value) > capacity:
            if capacity < 2:
                value = "\x00"
                result = 0
            else:
                value = value[:capacity - 2] + "\x00\x00"
                result = capacity - 2
        else:
            result = len(value) - 1
        machine.write(address, binary.encode(value, encoding = "utf16le" if wide else "ascii"))
        return result

    def write_file_data(path, offset, value, machine = None):
        end = offset + len(value)
        if offset < 0 or end > maximum_file_size:
            return False
        entry = state["paths"].get(path)
        if entry == None or entry.get("directory", False):
            return False
        data = entry_data(entry)
        output = binary.builder(capacity = max(1, max(len(data), end)), limit = maximum_file_size)
        output.append(data[:min(offset, len(data))])
        if offset > len(data):
            output.reserve(offset - len(data))
        output.append(value)
        if end < len(data):
            output.append(data[end:])
        updated = output.bytes()
        if updated != data:
            entry["data"] = updated
            entry["size"] = len(updated)
            entry["dirty"] = True
            # Shared file mappings observe writes made through file handles.
            # Keep modeled views coherent without requiring target code to
            # unmap and remap the file after every append or index update.
            if machine != None:
                write_end = offset + len(value)
                for address, view in state["views"].items():
                    mapping = view["mapping"]
                    if mapping["path"] != path:
                        continue
                    overlap_start = max(offset, view["offset"])
                    overlap_end = min(write_end, view["offset"] + view["size"])
                    if overlap_start < overlap_end:
                        machine.write(
                            address + overlap_start - view["offset"],
                            updated[overlap_start:overlap_end],
                        )
        return True

    def write_find_data(machine, address, path, wide):
        entry = state["paths"][path]
        machine.write(address, b"\x00" * (592 if wide else 320))
        machine.write_u32le(address, 0x10 if entry.get("directory", False) else 0x80)
        size = len(entry_data(entry))
        machine.write_u32le(address + 28, size >> 32)
        machine.write_u32le(address + 32, size & 0xffffffff)
        filename = path.rsplit("\\", 1)[-1]
        _write_string(machine, address + 44, filename[:259], wide, 260)

    def write_io_status(machine, address, status, information):
        if address:
            machine.write_u32le(address, status)
            machine.write_u32le(address + 4, information)

    def complete_overlapped(machine, address, transferred):
        if not address:
            return
        write_io_status(machine, address, 0, transferred)
        completion = state["handles"].get(machine.read_u32le(address + 16))
        if type(completion) == "dict" and completion.get("kind") == "event":
            completion["value"]["signaled"] = True

    state["write_file_data"] = write_file_data

    def flush_view(machine, address, count = 0):
        view = state["views"].get(address)
        if view == None:
            return False
        size = view["size"] if count == 0 else min(count, view["size"])
        data = machine.read(address, size)
        mapping = view["mapping"]
        if mapping["path"] != None:
            return write_file_data(mapping["path"], view["offset"], data, machine = machine)
        before = mapping["data"]
        start = view["offset"]
        end = start + size
        output = binary.builder(capacity = len(before))
        output.append(before[:start])
        output.append(data)
        output.append(before[end:])
        mapping["data"] = output.bytes()
        return True

    def module_name(value):
        name = value.replace("\\", "/").split("/")[-1].lower()
        return name if "." in name else name + ".dll"

    def find_module(machine, name = "", handle = 0):
        for loaded in machine.modules:
            if (name and loaded.name == module_name(name)) or (handle and loaded.base == handle):
                return {"name": loaded.name, "handle": loaded.base}
        requested = module_name(name) if name else ""
        for virtual_name, virtual_handle in state["modules"].items():
            if (requested and virtual_name == requested) or (handle and virtual_handle == handle):
                return {"name": virtual_name, "handle": virtual_handle}
        return None

    def load_module(machine, requested, api):
        """Resolves one module through the live in-memory loader namespace."""
        requested = module_name(requested)
        loaded = find_module(machine, name = requested)
        if api.startswith("loadlibrary") and on_module_load != None:
            # A native image may already be mapped but still await process
            # attach. The loader callback owns that state transition.
            handle = on_module_load(requested)
            if handle != None:
                if handle:
                    state["modules"][requested] = handle
                    state["handles"][handle] = requested
                    loaded = find_module(machine, name = requested)
                else:
                    loaded = None
        elif loaded == None and on_module_load != None:
            handle = on_module_load(requested)
            if handle:
                state["modules"][requested] = handle
                state["handles"][handle] = requested
                loaded = find_module(machine, name = requested)
        state["module_queries"].append({"api": api, "module": requested, "found": loaded != None})
        return loaded

    def search_path_exists(machine, path):
        normalized = _normalize_virtual_path(path)
        if normalized in state["paths"] and not state["paths"][normalized].get("directory", False):
            return True
        basename = normalized.replace("\\", "/").split("/")[-1]
        return find_module(machine, name = basename) != None

    def object_signaled(entry):
        kind = entry.get("kind")
        value = entry.get("value", {})
        return (
            kind == "event" and value.get("signaled", False) or
            kind == "mutex" or
            kind == "semaphore" and value.get("count", 0) > 0 or
            kind == "thread" and value.get("state") == "terminated"
        )

    def select_objects(entries, wait_all, consume):
        signaled = [object_signaled(entry) for entry in entries]
        selected = -1
        if wait_all:
            selected = 0 if False not in signaled else -1
        else:
            for index in range(len(signaled)):
                if selected < 0 and signaled[index]:
                    selected = index
        if selected < 0:
            return 0x102
        if consume:
            for index in range(len(entries)):
                if not wait_all and index != selected:
                    continue
                entry = entries[index]
                if entry.get("kind") == "event" and not entry["value"].get("manual_reset", False):
                    entry["value"]["signaled"] = False
                elif entry.get("kind") == "mutex":
                    entry["value"]["owned"] = True
                elif entry.get("kind") == "semaphore":
                    entry["value"]["count"] -= 1
        return selected

    def wait_entries(handles):
        entries = []
        for handle in handles:
            entry = state["handles"].get(handle)
            if type(entry) != "dict":
                return None
            entries.append(entry)
        return entries

    def wait_for_multiple_objects(machine, count, handles, wait_all, consume = True):
        if count == 0 or count > 64 or not handles:
            state["last_error"] = 87
            return 0xffffffff
        numbers = []
        for index in range(count):
            numbers.append(machine.read_u32le(handles + index * 4))
        entries = wait_entries(numbers)
        if entries == None:
            state["last_error"] = 6
            return 0xffffffff
        return select_objects(entries, wait_all, consume)

    def wait_expired(wait):
        deadline = wait.get("deadline")
        return deadline != None and state["tick_count"] >= deadline

    def wait_matches(wait, handles, wait_all):
        return wait != None and wait.get("handles") == handles and wait.get("all", False) == wait_all

    def wait_ready(wait):
        critical_section = wait.get("critical_section")
        if critical_section != None:
            lock = state["critical_sections"].get(critical_section)
            return lock == None or lock["owner"] in [None, wait.get("owner")]
        entries = wait_entries(wait["handles"])
        return entries != None and (select_objects(entries, wait.get("all", False), False) != 0x102 or wait_expired(wait))

    def execution_owner(machine):
        # Each resumable emulator execution has an isolated 64 KiB stack slot.
        # Its slot is a stable thread identity across cooperative slices.
        return machine.get_register("esp") >> 16

    def enter_critical_section(machine, address, wait):
        owner = execution_owner(machine)
        lock = state["critical_sections"].get(address)
        if lock == None:
            lock = {"owner": None, "depth": 0}
            state["critical_sections"][address] = lock
        if lock["owner"] in [None, owner]:
            lock["owner"] = owner
            lock["depth"] += 1
            current = state["current_thread"]
            if current != None:
                current.pop("wait", None)
            return True
        if wait:
            current = state["current_thread"]
            if current != None:
                current["wait"] = {"critical_section": address, "owner": owner}
            machine.stop(
                "wait",
                detail = "critical section 0x%x is owned by execution 0x%x; requester 0x%x" % (address, lock["owner"], owner),
            )
        return False

    def leave_critical_section(machine, address):
        lock = state["critical_sections"].get(address)
        owner = execution_owner(machine)
        if lock != None and lock["owner"] == owner:
            lock["depth"] -= 1
            if lock["depth"] == 0:
                lock["owner"] = None

    def release_execution_locks(machine):
        """Releases process-private locks abandoned by the current execution."""
        owner = execution_owner(machine)
        for lock in state["critical_sections"].values():
            if lock["owner"] == owner:
                lock["owner"] = None
                lock["depth"] = 0

    def thread_id_for_handle(handle):
        if handle == 0xfffffffe:
            return state["current_thread"]["id"] if state["current_thread"] != None else 8
        entry = state["handles"].get(handle)
        if type(entry) != "dict" or entry.get("kind") not in ["thread", "thread_reference"]:
            return None
        return entry["value"]["id"]

    def current_process_handle(handle):
        if handle == 0xffffffff:
            return True
        entry = state["handles"].get(handle)
        return type(entry) == "dict" and entry.get("kind") == "process_reference" and entry["value"].get("id") == 4

    def terminate_process(machine, handle, exit_code):
        if not current_process_handle(handle):
            state["last_error"] = 6  # ERROR_INVALID_HANDLE
            return 0
        state["process_exit_code"] = exit_code
        state["last_error"] = 0
        release_execution_locks(machine)
        machine.set_register("eax", exit_code)
        machine.stop("process-exit", detail = str(exit_code))
        return None

    def suspend_wait(machine, handles, wait_all, timeout, detail):
        current = state["current_thread"]
        if current != None:
            previous = current.get("wait")
            if wait_matches(previous, handles, wait_all) and wait_expired(previous):
                current.pop("wait", None)
                return False
            if not wait_matches(previous, handles, wait_all):
                current["wait"] = {
                    "handles": handles,
                    "all": wait_all,
                    "deadline": None if timeout == 0xffffffff else state["tick_count"] + timeout,
                }
        machine.stop("wait", detail = detail)
        return True

    def run_thread(machine, thread):
        execution = state["executions"].get(thread["handle"])
        if execution == None or execution.done:
            return False
        previous = state["current_thread"]
        state["current_thread"] = thread
        thread["state"] = "running"
        result = execution.run(instruction_limit = thread_instruction_limit)
        thread["total_steps"] = thread.get("total_steps", 0) + result.steps
        thread["result"] = result
        thread["state"] = _execution_thread_state(result.reason)
        if result.reason == "return":
            thread.pop("wait", None)
        elif result.reason == "budget":
            # An instruction slice is a scheduling boundary, not a terminal
            # thread state. Preserve the execution for a later scheduler pass.
            thread.pop("wait", None)
        elif result.reason != "wait":
            thread.pop("wait", None)
        result_record = thread.get("result_record")
        if result_record != None:
            result_record["reason"] = result.reason
            result_record["detail"] = result.detail
            result_record["value"] = result.value
            result_record["eip"] = result.eip
            result_record["steps"] = thread["total_steps"]
            result_record["slice_steps"] = result.steps
            result_record["recent"] = result.recent
            result_record["registers"] = result.registers
            result_record["trace"] = result.trace
            result_record["calls"] = result.calls
        state["current_thread"] = previous
        return True

    def pump_thread_slice(machine):
        progressed = False
        for thread in state["threads"]:
            current = state["current_thread"]
            if current != None and thread["handle"] == current["handle"]:
                continue
            if thread["state"] in ["created", "runnable"] or thread["state"] == "waiting" and wait_ready(thread.get("wait", {"handles": []})):
                progressed = run_thread(machine, thread) or progressed
        return progressed

    def pump_threads(machine):
        progressed = False
        # Each pass must either run a newly-created thread or consume a wake.
        # The bound protects malformed targets that continually recreate waits.
        for unused in range(max(1, len(state["threads"]) * 4)):
            current_progress = pump_thread_slice(machine)
            progressed = progressed or current_progress
            if not current_progress:
                deadlines = []
                for thread in state["threads"]:
                    current = state["current_thread"]
                    wait = thread.get("wait") if thread["state"] == "waiting" else None
                    if (current == None or thread["handle"] != current["handle"]) and wait != None and wait.get("deadline") != None:
                        deadlines.append(wait["deadline"])
                if not deadlines:
                    break
                state["tick_count"] = max(state["tick_count"], min(deadlines))
        return progressed

    def create_thread(event, stack_size, start, parameter, flags, thread_id_output, defer_start = False):
        machine = event.machine
        if not start:
            state["last_error"] = 87
            return 0
        thread = {
            "id": state["next_thread_id"],
            "start": start,
            "parameter": parameter,
            "stack_size": stack_size,
            "flags": flags,
            "state": "suspended" if flags & 0x4 else "created",
        }
        state["next_thread_id"] += 1
        handle = create_handle("thread", thread)
        thread["handle"] = handle
        state["threads"].append(thread)
        if thread_id_output:
            machine.write_u32le(thread_id_output, thread["id"])
        if on_thread_create == None:
            state["executions"][handle] = machine.spawn(thread["start"], args = [thread["parameter"]])
            if not flags & 0x4 and not defer_start:
                run_thread(machine, thread)
        elif not flags & 0x4:
            on_thread_create(event, thread)
        return handle

    state["wait_for_multiple_objects"] = wait_for_multiple_objects
    state["pump_thread_slice"] = pump_thread_slice
    state["pump_threads"] = pump_threads
    state["suspend_wait"] = suspend_wait
    state["create_thread"] = create_thread

    def character_type(code):
        flags = 0x200  # C1_DEFINED
        if code < 0x20 or code == 0x7f:
            flags |= 0x20  # C1_CNTRL
        if code in [9, 10, 11, 12, 13, 32]:
            flags |= 0x8  # C1_SPACE
        if code in [9, 32]:
            flags |= 0x40  # C1_BLANK
        if code >= 48 and code <= 57:
            flags |= 0x4 | 0x80  # C1_DIGIT | C1_XDIGIT
        elif code >= 65 and code <= 90:
            flags |= 0x1 | 0x100  # C1_UPPER | C1_ALPHA
            if code <= 70:
                flags |= 0x80
        elif code >= 97 and code <= 122:
            flags |= 0x2 | 0x100  # C1_LOWER | C1_ALPHA
            if code <= 102:
                flags |= 0x80
        elif code >= 0x21 and code <= 0x7e:
            flags |= 0x10  # C1_PUNCT
        return flags

    def terminated_data(machine, address, width, maximum = 65536):
        output = binary.builder(capacity = 64, limit = maximum * width)
        for unused in range(maximum):
            unit = machine.read(address, width)
            output.append(unit)
            address += width
            cursor = binary.cursor(unit)
            if (cursor.u16le() if width == 2 else cursor.u8()) == 0:
                return output.bytes()
        fail("character conversion input exceeds {} units".format(maximum))

    def padded(value, width):
        text = str(value)
        return "0" * max(0, width - len(text)) + text

    def date_text(pattern, year, month, day, day_of_week):
        months = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]
        weekdays = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
        output = ""
        index = 0
        quoted = False
        while index < len(pattern):
            character = pattern[index]
            if character == "'":
                if index + 1 < len(pattern) and pattern[index + 1] == "'":
                    output += "'"
                    index += 2
                    continue
                quoted = not quoted
                index += 1
                continue
            if quoted or character not in "dMyg":
                output += character
                index += 1
                continue
            end = index + 1
            while end < len(pattern) and pattern[end] == character:
                end += 1
            width = end - index
            if character == "d":
                if width == 1:
                    output += str(day)
                elif width == 2:
                    output += padded(day, 2)
                elif width == 3:
                    output += weekdays[day_of_week][:3]
                else:
                    output += weekdays[day_of_week]
            elif character == "M":
                if width == 1:
                    output += str(month)
                elif width == 2:
                    output += padded(month, 2)
                elif width == 3:
                    output += months[month - 1][:3]
                else:
                    output += months[month - 1]
            elif character == "y":
                output += padded(year % 100, 2) if width <= 2 else padded(year, max(4, width))
            else:
                output += "A.D."
            index = end
        return output

    def time_text(pattern, hour, minute, second):
        output = ""
        index = 0
        quoted = False
        while index < len(pattern):
            character = pattern[index]
            if character == "'":
                if index + 1 < len(pattern) and pattern[index + 1] == "'":
                    output += "'"
                    index += 2
                    continue
                quoted = not quoted
                index += 1
                continue
            if quoted or character not in "hHmst":
                output += character
                index += 1
                continue
            end = index + 1
            while end < len(pattern) and pattern[end] == character:
                end += 1
            width = end - index
            if character == "h":
                value = hour % 12
                value = 12 if value == 0 else value
                output += padded(value, 2) if width >= 2 else str(value)
            elif character == "H":
                output += padded(hour, 2) if width >= 2 else str(hour)
            elif character == "m":
                output += padded(minute, 2) if width >= 2 else str(minute)
            elif character == "s":
                output += padded(second, 2) if width >= 2 else str(second)
            else:
                marker = "AM" if hour < 12 else "PM"
                output += marker if width >= 2 else marker[:1]
            index = end
        return output

    def write_nt_query(machine, output_address, output_length, return_length_address, payload, result = 0):
        required = len(payload)
        if return_length_address:
            machine.write_u32le(return_length_address, required)
        if output_length < required:
            return 0xc0000004  # STATUS_INFO_LENGTH_MISMATCH
        if required and not output_address:
            return 0xc0000005  # STATUS_ACCESS_VIOLATION
        if required:
            machine.write(output_address, payload)
        return result

    def callback(event):
        name = event.name.lower()
        args = event.args
        machine = event.machine
        if name == "thunkconnect32":
            # Registration-time DllMain only requires acknowledgement of the
            # Win9x flat-thunk pair; it does not invoke a 16-bit target.
            return 1
        if name in ["globaladdatoma", "globaladdatomw"]:
            return 0xc000
        if name in ["rtlinitansistring", "rtlinitstring", "rtlinitunicodestring"]:
            wide = name == "rtlinitunicodestring"
            if not args[0]:
                return None
            if not args[1]:
                machine.write(args[0], b"\x00" * 8)
                return None
            text = machine.read_cstring(args[1], encoding = "utf16le" if wide else "ascii")
            length = len(text) * (2 if wide else 1)
            descriptor = binary.builder(capacity = 8)
            descriptor.u16le(length)
            descriptor.u16le(length + (2 if wide else 1))
            descriptor.u32le(args[1])
            machine.write(args[0], descriptor.bytes())
            return None
        if name == "dbgprint":
            value = machine.read_cstring(args[0], encoding = "ascii") if args[0] else ""
            if len(state["debug_output"]) < 4096:
                state["debug_output"].append(value)
            return len(value)
        if name in ["isbadreadptr", "isbadwriteptr", "isbadstringptra", "isbadstringptrw"]:
            return 1 if args[1] and not args[0] else 0
        if name == "rtlintegertounicodestring":
            if not args[2] or args[1] not in [2, 8, 10, 16]:
                return 0xc000000d
            digits = "0123456789ABCDEF"
            value = args[0] & 0xffffffff
            encoded = "0" if value == 0 else ""
            while value:
                encoded = digits[value % args[1]] + encoded
                value //= args[1]
            data = binary.encode(encoded, encoding = "utf16le")
            destination = binary.cursor(machine.read(args[2], 8))
            destination.u16le()
            capacity = destination.u16le()
            address = destination.u32le()
            if not address or capacity < len(data):
                return 0xc0000023
            machine.write(address, data)
            if capacity >= len(data) + 2:
                machine.write(address + len(data), b"\x00\x00")
            machine.write_u16le(args[2], len(data))
            return 0
        if name == "rtlcopyunicodestring":
            if not args[0]:
                return None
            destination = binary.cursor(machine.read(args[0], 8))
            destination.u16le()
            capacity = destination.u16le()
            address = destination.u32le()
            source_length = 0
            source_address = 0
            if args[1]:
                source = binary.cursor(machine.read(args[1], 8))
                source_length = source.u16le()
                source.u16le()
                source_address = source.u32le()
            copied = min(capacity, source_length) & ~1
            if address and copied:
                machine.write(address, machine.read(source_address, copied))
            if address and capacity >= copied + 2:
                machine.write(address + copied, b"\x00\x00")
            machine.write_u16le(args[0], copied)
            return None
        if name in ["ntqueryinformationprocess", "zwqueryinformationprocess"]:
            process_handle, info_class, output_address, output_length, return_length_address = args
            handle_entry = state["handles"].get(process_handle)
            valid_handle = process_handle == 0xffffffff or (type(handle_entry) == "dict" and handle_entry.get("kind") == "process_reference")
            if not valid_handle:
                result = 0xc0000008  # STATUS_INVALID_HANDLE
            else:
                payload = None
                result = 0
                if info_class == 0:  # ProcessBasicInformation
                    fs_base = machine.segment_base("fs")
                    peb = machine.read_u32le(fs_base + 0x30) if fs_base else 0
                    output = binary.builder(capacity = 24)
                    for value in [0x103, peb, 1, 8, 4, 0]:
                        output.u32le(value)
                    payload = output.bytes()
                elif info_class == 7:  # ProcessDebugPort
                    payload = b"\x00\x00\x00\x00"
                elif info_class == 26:  # ProcessWow64Information
                    payload = b"\x00\x00\x00\x00"
                elif info_class == 29:  # ProcessBreakOnTermination
                    payload = b"\x00\x00\x00\x00"
                elif info_class == 30:  # ProcessDebugObjectHandle
                    payload = b"\x00\x00\x00\x00"
                    result = 0xc0000353  # STATUS_PORT_NOT_SET
                elif info_class == 31:  # ProcessDebugFlags: nonzero means debugging disabled
                    payload = b"\x01\x00\x00\x00"
                else:
                    result = 0xc0000003  # STATUS_INVALID_INFO_CLASS
                if payload != None:
                    result = write_nt_query(machine, output_address, output_length, return_length_address, payload, result = result)
            state["process_queries"].append({"api": name, "class": info_class, "length": output_length, "result": result})
            return result
        if name in ["ntquerysysteminformation", "zwquerysysteminformation"]:
            info_class, output_address, output_length, return_length_address = args
            payload = None
            result = 0
            request = b""
            observation = None if on_system_query == None else on_system_query(machine, {
                "address": output_address,
                "api": name,
                "class": info_class,
                "length": output_length,
                "return_length_address": return_length_address,
            })
            provided = None if system_query_provider == None else system_query_provider(machine, {
                "address": output_address,
                "api": name,
                "class": info_class,
                "length": output_length,
                "return_length_address": return_length_address,
            })
            response = None
            if provided != None:
                if type(provided) != "dict" or "status" not in provided or "required_length" not in provided:
                    fail("system-query provider must return None or a response dict")
                result = int(provided["status"])
                required = int(provided["required_length"])
                short_status = int(provided.get("short_status", 0xc0000004))
                data = provided.get("data")
                if required < 0 or required > 16 << 20:
                    fail("system-query provider required length exceeds its bound")
                if data != None:
                    if type(data) not in ["bytes", "file"]:
                        fail("system-query provider data must be bytes or a file")
                    data = binary.view(data).bytes()
                    if len(data) > required:
                        fail("system-query provider data exceeds its required length")
                if return_length_address:
                    machine.write_u32le(return_length_address, required)
                if output_length < required:
                    result = short_status
                elif data != None:
                    if data and not output_address:
                        result = 0xc0000005  # STATUS_ACCESS_VIOLATION
                    elif data:
                        machine.write(output_address, data)
                response = {"data_size": 0 if data == None else len(data), "required_length": required, "status": result}
            elif info_class == 0:  # SystemBasicInformation, 32-bit layout
                output = binary.builder(capacity = 44)
                for value in [0, 156250, 4096, 131072, 0, 131071, 65536, 0x10000, 0x7ffeffff, 1]:
                    output.u32le(value)
                output.append(b"\x01\x00\x00\x00")
                payload = output.bytes()
            elif info_class == 35:  # SystemKernelDebuggerInformation
                payload = b"\x00\x01"
            else:
                result = 0xc0000003  # STATUS_INVALID_INFO_CLASS
                if output_address and output_length > 0:
                    request = machine.read(output_address, min(output_length, 64))
            if payload != None:
                result = write_nt_query(machine, output_address, output_length, return_length_address, payload, result = result)
            state["system_queries"].append({"api": name, "class": info_class, "length": output_length, "observation": observation, "request": request, "response": response, "result": result})
            return result
        if name == "etweventregister":
            if not args[3]:
                return 0xc000000d  # STATUS_INVALID_PARAMETER
            handle = state["next_etw_handle"]
            state["next_etw_handle"] = handle + 1
            machine.write_u64le(args[3], handle)
            return 0
        if name == "etweventunregister":
            return 0
        if name == "etweventenabled":
            return 0
        if name == "etweventwrite":
            return 0
        if name == "ntcreateport":
            if not args[0]:
                return 0xc000000d
            handle = create_handle("port")
            machine.write_u32le(args[0], handle)
            return 0
        if name == "ntcreateevent":
            if not args[0] or args[3] not in [0, 1]:
                return 0xc000000d
            handle = create_handle("event", {"manual_reset": args[3] == 0, "signaled": bool(args[4])})
            machine.write_u32le(args[0], handle)
            return 0
        if name == "ntopenevent":
            if args[0]:
                machine.write_u32le(args[0], 0)
            return 0xc0000034
        if name == "ntquerysystemtime":
            if not args[0]:
                return 0xc000000d
            output = binary.builder(capacity = 8)
            output.u64le(system_time_ticks)
            machine.write(args[0], output.bytes())
            return 0
        if name == "ntallocatelocallyuniqueid":
            if not args[0]:
                return 0xc000000d
            output = binary.builder(capacity = 8)
            output.u64le(state["next_luid"])
            state["next_luid"] += 1
            machine.write(args[0], output.bytes())
            return 0
        if name == "ntrequestwaitreplyport":
            if not args[0] or not args[1] or not args[2]:
                return 0xc000000d
            # LPC messages begin with 16-bit data and total lengths. Preserve
            # the request as a deterministic successful reply when no peer is
            # modeled.
            header = binary.cursor(machine.read(args[1], 4))
            header.u16le()
            total = header.u16le()
            if total < 16 or total > 65535:
                return 0xc000000d
            machine.write(args[2], machine.read(args[1], total))
            return 0
        if name == "ntsetevent":
            entry = state["handles"].get(args[0])
            if type(entry) != "dict" or entry.get("kind") != "event":
                return 0xc0000008
            previous = 1 if entry["value"].get("signaled", False) else 0
            entry["value"]["signaled"] = True
            if args[1]:
                machine.write_u32le(args[1], previous)
            return 0
        if name == "ntwaitforsingleobject":
            entry = state["handles"].get(args[0])
            if type(entry) != "dict":
                return 0xc0000008
            if object_signaled(entry):
                if entry.get("kind") == "event" and not entry["value"].get("manual_reset", False):
                    entry["value"]["signaled"] = False
                return 0
            return 0x102  # STATUS_TIMEOUT in the bounded semantic runtime
        if name in ["rtlansistringtounicodestring", "rtlunicodestringtoansistring"]:
            if not args[0] or not args[1]:
                return 0xc000000d
            source = binary.cursor(machine.read(args[1], 8))
            source_length = source.u16le()
            source.u16le()
            source_address = source.u32le()
            to_wide = name == "rtlansistringtounicodestring"
            text = binary.text(
                machine.read(source_address, source_length),
                encoding = "ascii" if to_wide else "utf16le",
            ) if source_length else ""
            data = binary.encode(text, encoding = "utf16le" if to_wide else "ascii")
            terminator = b"\x00\x00" if to_wide else b"\x00"
            terminated_builder = binary.builder(capacity = len(data) + len(terminator))
            terminated_builder.append(data)
            terminated_builder.append(terminator)
            terminated = terminated_builder.bytes()
            if args[2]:
                address = machine.allocate(value = terminated, name = name)
                state["local_allocations"][address] = len(data) + len(terminator)
                capacity = len(data) + len(terminator)
            else:
                destination = binary.cursor(machine.read(args[0], 8))
                destination.u16le()
                capacity = destination.u16le()
                address = destination.u32le()
                if not address or capacity < len(data):
                    return 0xc0000023
                machine.write(address, terminated if capacity >= len(terminated) else data)
            descriptor = binary.builder(capacity = 8)
            descriptor.u16le(len(data))
            descriptor.u16le(capacity)
            descriptor.u32le(address)
            machine.write(args[0], descriptor.bytes())
            return 0
        if name in ["rtlappendunicodestringtostring", "rtlappendunicodetostring"]:
            if not args[0] or not args[1]:
                return 0xc000000d
            destination = binary.cursor(machine.read(args[0], 8))
            destination_length = destination.u16le()
            destination_capacity = destination.u16le()
            destination_address = destination.u32le()
            if name == "rtlappendunicodestringtostring":
                source = binary.cursor(machine.read(args[1], 8))
                source_length = source.u16le()
                source.u16le()
                source_address = source.u32le()
            else:
                source_text = machine.read_cstring(args[1], encoding = "utf16le")
                source_length = len(source_text) * 2
                source_address = args[1]
            if not destination_address or destination_length + source_length > destination_capacity:
                return 0xc0000023
            if source_length:
                machine.write(destination_address + destination_length, machine.read(source_address, source_length))
            destination_length += source_length
            if destination_capacity >= destination_length + 2:
                machine.write(destination_address + destination_length, b"\x00\x00")
            machine.write_u16le(args[0], destination_length)
            return 0
        if name in ["rtlfreeansistring", "rtlfreeunicodestring"]:
            if args[0]:
                descriptor = binary.cursor(machine.read(args[0], 8))
                descriptor.u16le()
                descriptor.u16le()
                address = descriptor.u32le()
                if address in state["local_allocations"]:
                    state["local_allocations"].pop(address)
                    machine.free(address)
                machine.write(args[0], b"\x00" * 8)
            return None
        if name == "getprocessheap":
            return 1
        if name == "heapsetinformation":
            if args[0] and args[0] not in state["heaps"]:
                state["last_error"] = 6  # ERROR_INVALID_HANDLE
                return 0
            # Heap policy changes affect allocator strategy, not its ABI.
            state["last_error"] = 0
            return 1
        if name == "comparefiletime":
            left = machine.read_u64le(args[0])
            right = machine.read_u64le(args[1])
            return -1 if left < right else (1 if left > right else 0)
        if name == "filetimetodosdatetime":
            if not args[0] or not args[1] or not args[2]:
                state["last_error"] = 87
                return 0
            ticks = machine.read_u64le(args[0])
            total_seconds = ticks // 10000000
            days = total_seconds // 86400
            seconds = total_seconds % 86400
            year = 1601
            while True:
                leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
                year_days = 366 if leap else 365
                if days < year_days:
                    break
                days -= year_days
                year += 1
            month_days = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
            month = 1
            for count in month_days:
                if days < count:
                    break
                days -= count
                month += 1
            if year < 1980 or year > 2107:
                state["last_error"] = 87
                return 0
            hour = seconds // 3600
            minute = (seconds % 3600) // 60
            second = seconds % 60
            machine.write_u16le(args[1], ((year - 1980) << 9) | (month << 5) | (days + 1))
            machine.write_u16le(args[2], (hour << 11) | (minute << 5) | (second // 2))
            state["last_error"] = 0
            return 1
        if name == "dosdatetimetofiletime":
            if not args[2]:
                state["last_error"] = 87
                return 0
            date = args[0]
            time = args[1]
            ticks = _filetime_ticks(
                ((date >> 9) & 0x7f) + 1980,
                (date >> 5) & 0x0f,
                date & 0x1f,
                (time >> 11) & 0x1f,
                (time >> 5) & 0x3f,
                (time & 0x1f) * 2,
                0,
            )
            if ticks == None:
                state["last_error"] = 87
                return 0
            machine.write_u64le(args[2], ticks)
            state["last_error"] = 0
            return 1
        if name in ["comparestringa", "comparestringw"]:
            wide = name.endswith("w")
            encoding = "utf16le" if wide else "ascii"
            width = 2 if wide else 1
            left_size = args[3]
            right_size = args[5]
            left = machine.read_cstring(args[2], encoding = encoding) if left_size == 0xffffffff else binary.text(machine.read(args[2], left_size * width), encoding = encoding)
            right = machine.read_cstring(args[4], encoding = encoding) if right_size == 0xffffffff else binary.text(machine.read(args[4], right_size * width), encoding = encoding)
            if args[1] & 1:  # NORM_IGNORECASE
                left = left.lower()
                right = right.lower()
            return 1 if left < right else (3 if left > right else 2)
        if name in ["getcommandlinea", "getcommandlinew"]:
            address = state["command_lines"].get(name)
            if address == None:
                wide = name.endswith("w")
                value = _encoded(command_line, wide)
                address = machine.allocate(value = value, name = name)
                state["command_lines"][name] = address
            return address
        if name in ["getcomputernameexa", "getcomputernameexw"]:
            if not args[2] or args[0] > 7:
                state["last_error"] = 87  # ERROR_INVALID_PARAMETER
                return 0
            if args[0] in [0, 4]:
                value = computer_name
            elif args[0] in [1, 5]:
                value = dns_host_name
            elif args[0] in [2, 6]:
                value = dns_domain
            else:
                value = dns_host_name + ("." + dns_domain if dns_domain else "")
            capacity = machine.read_u32le(args[2])
            required = len(value) + 1
            if not args[1] or capacity < required:
                machine.write_u32le(args[2], required)
                state["last_error"] = 234  # ERROR_MORE_DATA
                return 0
            _write_string(machine, args[1], value, name.endswith("w"), capacity)
            machine.write_u32le(args[2], len(value))
            state["last_error"] = 0
            return 1
        if name in ["getcomputernamea", "getcomputernamew"]:
            capacity = machine.read_u32le(args[1]) if args[1] else 0
            if not args[0] or not args[1] or capacity <= len(computer_name):
                if args[1]:
                    machine.write_u32le(args[1], len(computer_name) + 1)
                state["last_error"] = 111  # ERROR_BUFFER_OVERFLOW
                return 0
            _write_string(machine, args[0], computer_name, name.endswith("w"), capacity)
            machine.write_u32le(args[1], len(computer_name))
            return 1
        if name in ["heapcreate", "rtlcreateheap"]:
            handle = create_handle("heap")
            state["heaps"][handle] = True
            return handle
        if name in ["heapdestroy", "rtldestroyheap"]:
            if args[0] == 1 or args[0] not in state["heaps"]:
                state["last_error"] = 6  # ERROR_INVALID_HANDLE
                return args[0] if name == "rtldestroyheap" else 0
            state["heaps"].pop(args[0])
            for address, allocation in list(state["allocations"].items()):
                if allocation["heap"] == args[0]:
                    state["allocations"].pop(address)
                    machine.free(address)
            return 0 if name == "rtldestroyheap" else 1
        if name == "getcurrentprocessid":
            return 4
        if name == "getcurrentprocess":
            return 0xffffffff
        if name == "getcurrentthreadid":
            return state["current_thread"]["id"] if state["current_thread"] != None else 8
        if name == "getcurrentthread":
            return 0xfffffffe
        if name == "duplicatehandle":
            source_process, source_handle, target_process, output, desired_access, inherit, options = args
            if source_process != 0xffffffff or target_process != 0xffffffff or not output:
                state["last_error"] = 6 if source_process != 0xffffffff or target_process != 0xffffffff else 87
                return 0
            if source_handle == 0xfffffffe:
                thread_id = state["current_thread"]["id"] if state["current_thread"] != None else 8
                duplicate = create_handle("thread_reference", {"id": thread_id})
            elif source_handle == 0xffffffff:
                duplicate = create_handle("process_reference", {"id": 4})
            else:
                source = state["handles"].get(source_handle)
                if type(source) != "dict":
                    state["last_error"] = 6
                    return 0
                duplicate = create_handle(source["kind"], source["value"])
            machine.write_u32le(output, duplicate)
            if options & 1 and source_handle not in [0xffffffff, 0xfffffffe]:
                state["handles"].pop(source_handle, None)
            state["last_error"] = 0
            return 1
        if name == "openthread":
            thread_id = args[2]
            known = thread_id == 8
            for thread in state["threads"]:
                known = known or thread["id"] == thread_id
            if not known:
                state["last_error"] = 87
                return 0
            state["last_error"] = 0
            return create_handle("thread_reference", {"id": thread_id})
        if name == "openprocess":
            process_id = args[2]
            if process_id != 4:
                state["last_error"] = 87
                return 0
            state["last_error"] = 0
            return create_handle("process_reference", {
                "id": process_id,
                "access": args[0],
                "inherit": bool(args[1]),
            })
        if name in ["getthreadpriority", "setthreadpriority"]:
            handle = args[0]
            thread_id = state["current_thread"]["id"] if state["current_thread"] != None else 8
            if handle != 0xfffffffe:
                entry = state["handles"].get(handle)
                if type(entry) != "dict" or entry.get("kind") not in ["thread", "thread_reference"]:
                    state["last_error"] = 6
                    return 0x7fffffff if name == "getthreadpriority" else 0
                thread_id = entry["value"]["id"]
            if name == "getthreadpriority":
                return state["thread_priorities"].get(thread_id, 0)
            state["thread_priorities"][thread_id] = args[1]
            state["last_error"] = 0
            return 1
        if name in ["decodepointer", "encodepointer"]:
            # The isolated address space has no disclosure boundary requiring
            # process-cookie obfuscation. Identity preserves round trips.
            return args[0]
        if name == "getsystempowerstatus":
            if not args[0]:
                state["last_error"] = 87
                return 0
            machine.write(args[0], _system_power_status())
            state["last_error"] = 0
            return 1
        if name == "gettickcount":
            return state["tick_count"] & 0xffffffff
        if name == "sleep":
            state["tick_count"] += args[0]
            pump_threads(machine)
            return None
        if name in ["outputdebugstringa", "outputdebugstringw"]:
            return None
        if name == "switchtothread":
            return 0
        if name == "createthread":
            return create_thread(event, args[1], args[2], args[3], args[4], args[5])
        if name == "queueuserworkitem":
            handle = create_thread(event, 0, args[0], args[1], 0, 0, defer_start = True)
            if not handle:
                return 0
            state["last_error"] = 0
            return 1
        if name == "resumethread":
            entry = state["handles"].get(args[0])
            if type(entry) != "dict" or entry.get("kind") != "thread":
                state["last_error"] = 6
                return 0xffffffff
            thread = entry["value"]
            previous = 1 if thread["state"] == "suspended" else 0
            if previous:
                thread["state"] = "created"
                if on_thread_create == None:
                    run_thread(machine, thread)
                else:
                    on_thread_create(event, thread)
            return previous
        if name == "getexitcodethread":
            entry = state["handles"].get(args[0])
            if type(entry) != "dict" or entry.get("kind") != "thread" or not args[1]:
                state["last_error"] = 6 if type(entry) != "dict" or entry.get("kind") != "thread" else 87
                return 0
            result = entry["value"].get("result")
            machine.write_u32le(args[1], result.value if result != None and result.reason == "return" else 259)
            return 1
        if name == "registerwaitforsingleobject":
            if not args[0] or not args[1] or not args[2] or args[1] not in state["handles"]:
                state["last_error"] = 87 if not args[0] or not args[1] or not args[2] else 6
                return 0
            handle = create_handle("registered_wait", {
                "object": args[1], "callback": args[2], "context": args[3],
                "timeout": args[4], "flags": args[5], "pending": True,
            })
            machine.write_u32le(args[0], handle)
            state["last_error"] = 0
            return 1
        if name in ["unregisterwait", "unregisterwaitex"]:
            entry = state["handles"].get(args[0])
            if type(entry) != "dict" or entry.get("kind") != "registered_wait":
                state["last_error"] = 6
                return 0
            state["handles"].pop(args[0])
            if name == "unregisterwaitex" and args[1] not in [0, 0xffffffff]:
                completion = state["handles"].get(args[1])
                if type(completion) == "dict" and completion.get("kind") == "event":
                    completion["value"]["signaled"] = True
            state["last_error"] = 0
            return 1
        if name == "exitprocess":
            return terminate_process(machine, 0xffffffff, args[0])
        if name == "terminateprocess":
            return terminate_process(machine, args[0], args[1])
        if name == "exitthread":
            machine.transfer(address = 0)
            return None
        if name == "createtimerqueue":
            return create_handle("timer_queue")
        if name == "createtimerqueuetimer":
            output, queue, callback, parameter, due_time, period, flags = args
            if not output or not callback:
                state["last_error"] = 87
                return 0
            if queue:
                entry = state["handles"].get(queue)
                if type(entry) != "dict" or entry.get("kind") != "timer_queue":
                    state["last_error"] = 6
                    return 0
            timer = create_handle("timer", {"queue": queue, "callback": callback, "parameter": parameter, "due_time": due_time, "period": period, "flags": flags})
            machine.write_u32le(output, timer)
            if due_time == 0:
                result_record = {
                    "timer": timer,
                    "callback": callback,
                    "reason": "created",
                    "detail": "",
                    "value": 0,
                    "eip": callback,
                    "steps": 0,
                    "recent": [],
                    "registers": None,
                    "trace": [],
                }
                thread = {
                    "id": state["next_thread_id"],
                    "start": callback,
                    "parameter": parameter,
                    "stack_size": 0,
                    "flags": 0,
                    "state": "created",
                    "handle": timer,
                    "result_record": result_record,
                }
                state["next_thread_id"] += 1
                state["threads"].append(thread)
                state["executions"][timer] = machine.spawn(callback, args = [parameter, 1])
                state["timer_callbacks"].append(result_record)
                run_thread(machine, thread)
                state["handles"][timer]["value"]["result"] = thread.get("result")
            return 1
        if name == "changetimerqueuetimer":
            entry = state["handles"].get(args[1])
            if type(entry) != "dict" or entry.get("kind") != "timer" or entry["value"]["queue"] != args[0]:
                state["last_error"] = 6
                return 0
            entry["value"]["due_time"] = args[2]
            entry["value"]["period"] = args[3]
            return 1
        if name in ["deletetimerqueue", "deletetimerqueueex"]:
            queue = state["handles"].get(args[0])
            if type(queue) != "dict" or queue.get("kind") != "timer_queue":
                state["last_error"] = 6
                return 0
            timers = []
            for handle, entry in state["handles"].items():
                if type(entry) == "dict" and entry.get("kind") == "timer" and entry["value"]["queue"] == args[0]:
                    timers.append(handle)
            for handle in timers:
                state["handles"].pop(handle)
            state["handles"].pop(args[0])
            if name == "deletetimerqueueex" and args[1] not in [0, 0xffffffff]:
                completion = state["handles"].get(args[1])
                if type(completion) == "dict" and completion.get("kind") == "event":
                    completion["value"]["signaled"] = True
            return 1
        if name == "deletetimerqueuetimer":
            timer = state["handles"].get(args[1])
            if type(timer) != "dict" or timer.get("kind") != "timer" or timer["value"]["queue"] != args[0]:
                state["last_error"] = 6
                return 0
            state["handles"].pop(args[1])
            if args[2] not in [0, 0xffffffff]:
                completion = state["handles"].get(args[2])
                if type(completion) == "dict" and completion.get("kind") == "event":
                    completion["value"]["signaled"] = True
            return 1
        if name == "delayloadfailurehook":
            return 0
        if name in ["createeventa", "createeventw"]:
            wide = name.endswith("w")
            object_name = machine.read_cstring(args[3], encoding = "utf16le" if wide else "ascii") if args[3] else ""
            if object_name:
                for handle, entry in state["handles"].items():
                    if type(entry) == "dict" and entry.get("kind") == "event" and entry["value"].get("name", "").lower() == object_name.lower():
                        state["last_error"] = 183
                        return handle
            state["last_error"] = 0
            return create_handle("event", {"name": object_name, "manual_reset": bool(args[1]), "signaled": bool(args[2])})
        if name in ["openeventa", "openeventw"]:
            wide = name.endswith("w")
            object_name = machine.read_cstring(args[2], encoding = "utf16le" if wide else "ascii") if args[2] else ""
            for handle, entry in state["handles"].items():
                if type(entry) == "dict" and entry.get("kind") == "event" and entry["value"].get("name", "").lower() == object_name.lower():
                    state["last_error"] = 0
                    return handle
            state["last_error"] = 2
            return 0
        if name in ["createsemaphorea", "createsemaphorew"]:
            if args[1] > args[2] or args[2] == 0:
                state["last_error"] = 87
                return 0
            wide = name.endswith("w")
            object_name = machine.read_cstring(args[3], encoding = "utf16le" if wide else "ascii") if args[3] else ""
            if object_name:
                for handle, entry in state["handles"].items():
                    if type(entry) == "dict" and entry.get("kind") == "semaphore" and entry["value"].get("name", "").lower() == object_name.lower():
                        state["last_error"] = 183
                        return handle
            state["last_error"] = 0
            return create_handle("semaphore", {"name": object_name, "count": args[1], "maximum": args[2]})
        if name == "releasesemaphore":
            entry = state["handles"].get(args[0])
            if type(entry) != "dict" or entry.get("kind") != "semaphore":
                state["last_error"] = 6
                return 0
            value = entry["value"]
            if args[1] == 0 or value["count"] + args[1] > value["maximum"]:
                state["last_error"] = 298  # ERROR_TOO_MANY_POSTS
                return 0
            if args[2]:
                machine.write_u32le(args[2], value["count"])
            value["count"] += args[1]
            return 1
        if name in ["createmutexa", "createmutexw"]:
            wide = name.endswith("w")
            mutex_name = machine.read_cstring(args[2], encoding = "utf16le" if wide else "ascii") if args[2] else ""
            for handle, entry in state["handles"].items():
                if type(entry) == "dict" and entry.get("kind") == "mutex" and entry["value"].get("name", "").lower() == mutex_name.lower():
                    state["last_error"] = 183  # ERROR_ALREADY_EXISTS
                    return handle
            state["last_error"] = 0
            return create_handle("mutex", {"name": mutex_name, "owned": bool(args[1])})
        if name in ["openmutexa", "openmutexw"]:
            wide = name.endswith("w")
            mutex_name = machine.read_cstring(args[2], encoding = "utf16le" if wide else "ascii") if args[2] else ""
            for handle, entry in state["handles"].items():
                if type(entry) == "dict" and entry.get("kind") == "mutex" and entry["value"].get("name", "").lower() == mutex_name.lower():
                    state["last_error"] = 0
                    return handle
            state["last_error"] = 2
            return 0
        if name == "releasemutex":
            handle = state["handles"].get(args[0])
            if type(handle) != "dict" or handle.get("kind") != "mutex":
                state["last_error"] = 6
                return 0
            handle["value"]["owned"] = False
            return 1
        if name in ["setevent", "resetevent"]:
            handle = state["handles"].get(args[0])
            if type(handle) != "dict" or handle.get("kind") != "event":
                state["last_error"] = 6
                return 0
            handle["value"]["signaled"] = name == "setevent"
            return 1
        if name in ["waitforsingleobject", "waitforsingleobjectex"]:
            handle = state["handles"].get(args[0])
            if type(handle) != "dict":
                state["last_error"] = 6
                return 0xffffffff
            selected = select_objects([handle], False, True)
            if selected != 0x102:
                current = state["current_thread"]
                if current != None:
                    current.pop("wait", None)
                return selected
            if args[1] == 0:
                return 0x102
            pump_threads(machine)
            selected = select_objects([handle], False, True)
            if selected != 0x102:
                current = state["current_thread"]
                if current != None:
                    current.pop("wait", None)
                return selected
            suspend_wait(machine, [args[0]], False, args[1], "kernel single-object wait")
            return 0x102
        if name in ["waitformultipleobjects", "waitformultipleobjectsex"]:
            result = wait_for_multiple_objects(machine, args[0], args[1], args[2] != 0)
            numbers = []
            if result == 0x102:
                numbers = [machine.read_u32le(args[1] + index * 4) for index in range(args[0])]
            if result == 0x102 and args[3] != 0:
                pump_threads(machine)
                result = wait_for_multiple_objects(machine, args[0], args[1], args[2] != 0)
            if result != 0x102:
                current = state["current_thread"]
                if current != None:
                    current.pop("wait", None)
            elif args[3] != 0:
                suspend_wait(machine, numbers, args[2] != 0, args[3], "kernel multiple-object wait")
            return result
        if name in ["getfileattributesa", "getfileattributesw"]:
            target = file_path(machine, args[0], name.endswith("w"))
            existing = state["paths"].get(target)
            state["file_queries"].append({"api": name, "path": target, "found": existing != None})
            if existing != None:
                return 0x10 if existing["directory"] else 0x80
            state["last_error"] = 2  # ERROR_FILE_NOT_FOUND
            return 0xffffffff
        if name in ["getfileattributesexa", "getfileattributesexw"]:
            target = file_path(machine, args[0], name.endswith("w"))
            existing = state["paths"].get(target)
            state["file_queries"].append({"api": name, "path": target, "found": existing != None})
            if args[1] != 0 or not args[2]:
                state["last_error"] = 87  # ERROR_INVALID_PARAMETER
                return 0
            if existing == None:
                state["last_error"] = 2
                return 0
            size = len(entry_data(existing))
            data = binary.builder(capacity = 36)
            data.u32le(0x10 if existing["directory"] else 0x80)
            data.reserve(24)  # creation, access, and write FILETIMEs
            data.u32le((size >> 32) & 0xffffffff)
            data.u32le(size & 0xffffffff)
            machine.write(args[2], data.bytes())
            state["last_error"] = 0
            return 1
        if name == "getfilesize":
            opened = file_handle(args[0])
            if opened == None:
                state["last_error"] = 6
                return 0xffffffff
            size = len(file_data(opened["path"]))
            state["file_queries"].append({"api": name, "path": opened["path"], "size": size})
            if args[1]:
                machine.write_u32le(args[1], size >> 32)
            state["last_error"] = 0
            return size & 0xffffffff
        if name == "getfilesizeex":
            opened = file_handle(args[0])
            if opened == None or not args[1]:
                state["last_error"] = 6 if opened == None else 87
                return 0
            size = len(file_data(opened["path"]))
            state["file_queries"].append({"api": name, "path": opened["path"], "size": size})
            encoded = binary.builder(capacity = 8)
            encoded.u32le(size & 0xffffffff)
            encoded.u32le((size >> 32) & 0xffffffff)
            machine.write(args[1], encoded.bytes())
            state["last_error"] = 0
            return 1
        if name in ["getdrivetypea", "getdrivetypew"]:
            target = file_path(machine, args[0], name.endswith("w")) if args[0] else ""
            if target.startswith("\\\\"):
                return 4  # DRIVE_REMOTE
            return 3 if len(target) >= 2 and target[1] == ":" else 1  # DRIVE_FIXED / DRIVE_NO_ROOT_DIR
        if name in ["findfirstchangenotificationa", "findfirstchangenotificationw"]:
            target = file_path(machine, args[0], name.endswith("w"))
            return create_handle("change_notification", {"path": target, "subtree": args[1] != 0, "filter": args[2], "signaled": False})
        if name == "findnextchangenotification":
            entry = state["handles"].get(args[0])
            if entry == None or entry.get("kind") != "change_notification":
                state["last_error"] = 6
                return 0
            entry["value"]["signaled"] = False
            return 1
        if name == "findclosechangenotification":
            entry = state["handles"].get(args[0])
            if entry == None or entry.get("kind") != "change_notification":
                state["last_error"] = 6
                return 0
            state["handles"].pop(args[0])
            return 1
        if name in ["findfirstfilea", "findfirstfilew"]:
            wide = name.endswith("w")
            if not args[0] or not args[1]:
                state["last_error"] = 87
                return 0xffffffff
            pattern = file_path(machine, args[0], wide)
            parent, leaf = pattern.rsplit("\\", 1) if "\\" in pattern else ("", pattern)
            matches = []
            for path in state["paths"]:
                candidate_parent, candidate_name = path.rsplit("\\", 1) if "\\" in path else ("", path)
                if candidate_parent == parent and _wildcard_match(leaf, candidate_name):
                    matches.append(path)
            matches = sorted(matches)
            state["file_queries"].append({"api": name, "path": pattern, "matches": len(matches)})
            if not matches:
                parent_entry = state["paths"].get(parent)
                state["last_error"] = 2 if parent_entry != None and parent_entry.get("directory", False) else 3
                return 0xffffffff
            handle = create_handle("find", {"matches": matches, "index": 0, "wide": wide})
            write_find_data(machine, args[1], matches[0], wide)
            state["last_error"] = 0
            return handle
        if name in ["findnextfilea", "findnextfilew"]:
            entry = state["handles"].get(args[0])
            if type(entry) != "dict" or entry.get("kind") != "find" or not args[1]:
                state["last_error"] = 6 if type(entry) != "dict" or entry.get("kind") != "find" else 87
                return 0
            search = entry["value"]
            search["index"] += 1
            if search["index"] >= len(search["matches"]):
                state["last_error"] = 18  # ERROR_NO_MORE_FILES
                return 0
            write_find_data(machine, args[1], search["matches"][search["index"]], search["wide"])
            state["last_error"] = 0
            return 1
        if name == "findclose":
            entry = state["handles"].get(args[0])
            if type(entry) != "dict" or entry.get("kind") != "find":
                state["last_error"] = 6
                return 0
            state["handles"].pop(args[0])
            state["last_error"] = 0
            return 1
        if name in ["gettemppatha", "gettemppathw"]:
            wide = name.endswith("w")
            target = environment.get("TEMP", environment.get("TMP", windows_directory + "\\TEMP")).replace("/", "\\").rstrip("\\") + "\\"
            required = len(target) + 1
            if args[0] < required or not args[1]:
                return required
            _write_string(machine, args[1], target, wide, args[0])
            return len(target)
        if name in ["searchpatha", "searchpathw"]:
            wide = name.endswith("w")
            encoding = "utf16le" if wide else "ascii"
            if not args[1]:
                state["last_error"] = 87  # ERROR_INVALID_PARAMETER
                return 0
            filename = machine.read_cstring(args[1], encoding = encoding).replace("/", "\\")
            extension = machine.read_cstring(args[2], encoding = encoding) if args[2] else ""
            leaf = filename.replace("\\", "/").split("/")[-1]
            if extension and "." not in leaf:
                filename += extension
            candidates = []
            if "\\" in filename or (len(filename) >= 2 and filename[1] == ":"):
                candidates.append(filename)
            else:
                if args[0]:
                    directories = machine.read_cstring(args[0], encoding = encoding).split(";")
                else:
                    current = normalized_module.replace("/", "\\").rsplit("\\", 1)[0]
                    directories = [current, windows_directory + "\\system32", windows_directory]
                    path_value = environment.get("PATH", environment.get("Path", ""))
                    if path_value:
                        directories += path_value.split(";")
                for directory in directories:
                    directory = directory.replace("/", "\\").rstrip("\\")
                    candidates.append((directory + "\\" if directory else "") + filename)
            found = None
            for candidate in candidates:
                if found == None and search_path_exists(machine, candidate):
                    found = candidate
            state["file_queries"].append({"api": name, "name": filename, "path": found or "", "found": found != None})
            if found == None:
                state["last_error"] = 2  # ERROR_FILE_NOT_FOUND
                return 0
            required = len(found) + 1
            if not args[4] or args[3] < required:
                return required
            _write_string(machine, args[4], found, wide, args[3])
            if args[5]:
                separator = found.rfind("\\")
                machine.write_u32le(args[5], args[4] + (separator + 1) * (2 if wide else 1))
            state["last_error"] = 0
            return len(found)
        if name in ["gettempfilenamea", "gettempfilenamew"]:
            wide = name.endswith("w")
            if not args[0] or not args[3]:
                state["last_error"] = 87
                return 0
            directory = machine.read_cstring(args[0], encoding = "utf16le" if wide else "ascii").replace("/", "\\").rstrip("\\")
            prefix = machine.read_cstring(args[1], encoding = "utf16le" if wide else "ascii")[:3] if args[1] else "tmp"
            unique = args[2] & 0xffff
            if unique == 0:
                unique = state["next_temp"]
                state["next_temp"] += 1
            suffix = ("0000" + hex(unique)[2:])[-4:]
            target = directory + "\\" + prefix + suffix + ".tmp"
            _write_string(machine, args[3], target, wide)
            if args[2] == 0:
                state["paths"][_normalize_virtual_path(target)] = {"directory": False, "data": b"", "dirty": True}
            state["last_error"] = 0
            return unique
        if name in ["createdirectorya", "createdirectoryw"]:
            target = file_path(machine, args[0], name.endswith("w"))
            state["file_queries"].append({"api": name, "path": target})
            if target in state["paths"]:
                state["last_error"] = 183  # ERROR_ALREADY_EXISTS
                return 0
            state["paths"][target] = {"directory": True}
            state["last_error"] = 0
            return 1
        if name in ["removedirectorya", "removedirectoryw"]:
            target = file_path(machine, args[0], name.endswith("w"))
            existing = state["paths"].get(target)
            state["file_queries"].append({"api": name, "path": target, "found": existing != None})
            if existing == None or not existing.get("directory", False):
                state["last_error"] = 3  # ERROR_PATH_NOT_FOUND
                return 0
            prefix = target + "\\"
            if any([path.startswith(prefix) for path in state["paths"]]):
                state["last_error"] = 145  # ERROR_DIR_NOT_EMPTY
                return 0
            state["paths"].pop(target)
            state["last_error"] = 0
            return 1
        if name in ["createfilea", "createfilew"]:
            target = file_path(machine, args[0], name.endswith("w"))
            disposition = args[4]
            flags = args[5]
            existing = state["paths"].get(target)
            state["file_queries"].append({"api": name, "path": target, "found": existing != None, "disposition": disposition, "flags": flags})
            if existing != None and existing.get("directory", False):
                state["last_error"] = 5  # ERROR_ACCESS_DENIED
                return 0xffffffff
            if disposition == 1:  # CREATE_NEW
                if existing != None:
                    state["last_error"] = 80  # ERROR_FILE_EXISTS
                    return 0xffffffff
                state["paths"][target] = {"directory": False, "data": b"", "dirty": True}
            elif disposition == 2:  # CREATE_ALWAYS
                state["paths"][target] = {"directory": False, "data": b"", "dirty": True}
                state["last_error"] = 183 if existing != None else 0
            elif disposition == 3:  # OPEN_EXISTING
                if existing == None:
                    state["last_error"] = 2
                    return 0xffffffff
            elif disposition == 4:  # OPEN_ALWAYS
                if existing == None:
                    state["paths"][target] = {"directory": False, "data": b"", "dirty": True}
                    state["last_error"] = 0
                else:
                    state["last_error"] = 183
            elif disposition == 5:  # TRUNCATE_EXISTING
                if existing == None:
                    state["last_error"] = 2
                    return 0xffffffff
                existing["data"] = b""
                existing["size"] = 0
                existing["dirty"] = True
            else:
                state["last_error"] = 87  # ERROR_INVALID_PARAMETER
                return 0xffffffff
            return create_handle("file", {"path": target, "offset": 0, "overlapped": bool(flags & 0x40000000)})
        if name == "readfile":
            opened = file_handle(args[0])
            if opened == None or not args[1] or args[2] > maximum_file_size:
                state["last_error"] = 6 if opened == None else 87
                return 0
            position = opened["offset"]
            if args[4]:
                position = machine.read_u64le(args[4] + 8)
                if position > maximum_file_size:
                    state["last_error"] = 87
                    return 0
            data = file_data(opened["path"])
            value = data[position:position + args[2]]
            asynchronous = args[4] != 0 and opened.get("overlapped", False)
            state["file_queries"].append({"api": name, "path": opened["path"], "offset": position, "requested": args[2], "read": len(value), "overlapped": asynchronous})
            machine.write(args[1], value)
            if not asynchronous:
                opened["offset"] = position + len(value)
            if args[3]:
                machine.write_u32le(args[3], len(value))
            complete_overlapped(machine, args[4], len(value))
            state["last_error"] = 0
            return 1
        if name == "writefile":
            opened = file_handle(args[0])
            if opened == None or not args[1] or args[2] > maximum_file_size:
                state["last_error"] = 6 if opened == None else 87
                return 0
            value = machine.read(args[1], args[2])
            offset = opened["offset"]
            if args[4]:
                offset = machine.read_u64le(args[4] + 8)
                if offset > maximum_file_size:
                    state["last_error"] = 87
                    return 0
            if not write_file_data(opened["path"], offset, value, machine = machine):
                state["last_error"] = 112  # ERROR_DISK_FULL
                return 0
            asynchronous = args[4] != 0 and opened.get("overlapped", False)
            if not asynchronous:
                opened["offset"] = offset + len(value)
            state["file_queries"].append({"api": name, "path": opened["path"], "offset": offset, "written": len(value), "overlapped": asynchronous})
            if args[3]:
                machine.write_u32le(args[3], len(value))
            complete_overlapped(machine, args[4], len(value))
            state["last_error"] = 0
            return 1
        if name == "ntwritefile":
            opened = file_handle(args[0])
            if opened == None:
                write_io_status(machine, args[4], 0xc0000008, 0)  # STATUS_INVALID_HANDLE
                return 0xc0000008
            if args[2]:
                write_io_status(machine, args[4], 0xc00000bb, 0)  # STATUS_NOT_SUPPORTED
                return 0xc00000bb
            if args[6] > maximum_file_size or (args[6] and not args[5]):
                write_io_status(machine, args[4], 0xc000000d, 0)  # STATUS_INVALID_PARAMETER
                return 0xc000000d
            position = opened["offset"]
            update_position = True
            if args[7]:
                offset = machine.read_u64le(args[7])
                if offset == 0xffffffffffffffff:  # FILE_WRITE_TO_END_OF_FILE
                    position = len(file_data(opened["path"]))
                elif offset != 0xfffffffffffffffe:  # FILE_USE_FILE_POINTER_POSITION
                    if offset & (1 << 63):
                        write_io_status(machine, args[4], 0xc000000d, 0)
                        return 0xc000000d
                    position = offset
                    update_position = False
            value = machine.read(args[5], args[6]) if args[6] else b""
            if not write_file_data(opened["path"], position, value, machine = machine):
                write_io_status(machine, args[4], 0xc000007f, 0)  # STATUS_DISK_FULL
                return 0xc000007f
            if update_position:
                opened["offset"] = position + len(value)
            state["file_queries"].append({"api": name, "path": opened["path"], "offset": position, "written": len(value)})
            write_io_status(machine, args[4], 0, len(value))
            event = state["handles"].get(args[1]) if args[1] else None
            if type(event) == "dict" and event.get("kind") == "event":
                event["value"]["signaled"] = True
            return 0
        if name == "setfilepointer":
            opened = file_handle(args[0])
            if opened == None:
                state["last_error"] = 6
                return 0xffffffff
            high = machine.read_u32le(args[2]) if args[2] else (0xffffffff if args[1] & 0x80000000 else 0)
            distance = (high << 32) | args[1]
            if distance & (1 << 63):
                distance -= 1 << 64
            origin = 0 if args[3] == 0 else (opened["offset"] if args[3] == 1 else len(file_data(opened["path"])))
            position = origin + distance
            if args[3] > 2 or position < 0 or position > maximum_file_size:
                state["last_error"] = 87
                return 0xffffffff
            opened["offset"] = position
            state["file_queries"].append({"api": name, "path": opened["path"], "position": position, "origin": args[3]})
            if args[2]:
                machine.write_u32le(args[2], position >> 32)
            state["last_error"] = 0
            return position & 0xffffffff
        if name == "setfilepointerex":
            opened = file_handle(args[0])
            if opened == None:
                state["last_error"] = 6
                return 0
            distance = (args[2] << 32) | args[1]
            if distance & (1 << 63):
                distance -= 1 << 64
            origin = 0 if args[4] == 0 else (opened["offset"] if args[4] == 1 else len(file_data(opened["path"])))
            position = origin + distance
            if args[4] > 2 or position < 0 or position > maximum_file_size:
                state["last_error"] = 87
                return 0
            opened["offset"] = position
            state["file_queries"].append({"api": name, "path": opened["path"], "position": position, "origin": args[4]})
            if args[3]:
                encoded = binary.builder(capacity = 8)
                encoded.u32le(position & 0xffffffff)
                encoded.u32le((position >> 32) & 0xffffffff)
                machine.write(args[3], encoded.bytes())
            state["last_error"] = 0
            return 1
        if name == "setendoffile":
            opened = file_handle(args[0])
            if opened == None:
                state["last_error"] = 6
                return 0
            entry = state["paths"][opened["path"]]
            data = entry_data(entry)
            size = opened["offset"]
            output = binary.builder(capacity = max(1, size), limit = maximum_file_size)
            output.append(data[:min(size, len(data))])
            if size > len(data):
                output.reserve(size - len(data))
            updated = output.bytes()
            if updated != data:
                entry["data"] = updated
                entry["size"] = len(updated)
                entry["dirty"] = True
            return 1
        if name == "setfiletime":
            opened = file_handle(args[0])
            if opened == None:
                state["last_error"] = 6  # ERROR_INVALID_HANDLE
                return 0
            entry = state["paths"][opened["path"]]
            for key, pointer in [("creation_time", args[1]), ("access_time", args[2]), ("write_time", args[3])]:
                if pointer:
                    entry[key] = machine.read_u64le(pointer)
            state["last_error"] = 0
            return 1
        if name == "flushfilebuffers":
            if file_handle(args[0]) == None:
                state["last_error"] = 6
                return 0
            return 1
        if name in ["copyfilea", "copyfilew"]:
            wide = name.endswith("w")
            source = file_path(machine, args[0], wide)
            target = file_path(machine, args[1], wide)
            existing = state["paths"].get(source)
            state["file_queries"].append({"api": name, "path": source, "target": target, "found": existing != None})
            if existing == None:
                state["last_error"] = 2
                return 0
            if existing.get("directory", False):
                state["last_error"] = 5
                return 0
            if target in state["paths"] and args[2]:
                state["last_error"] = 80
                return 0
            state["paths"][target] = {
                "directory": False,
                "data": entry_data(existing),
                "dirty": True,
            }
            state["last_error"] = 0
            return 1
        if name in ["movefilea", "movefilew", "movefileexa", "movefileexw"]:
            wide = name.endswith("w")
            source = file_path(machine, args[0], wide)
            target = file_path(machine, args[1], wide) if args[1] else ""
            flags = args[2] if name.startswith("movefileex") else 0
            existing = state["paths"].get(source)
            state["file_queries"].append({"api": name, "path": source, "target": target, "found": existing != None})
            if existing == None:
                state["last_error"] = 2
                return 0
            if not target:
                state["paths"].pop(source)
                return 1
            if target in state["paths"] and (flags & 1) == 0:
                state["last_error"] = 183
                return 0
            existing["dirty"] = True
            state["paths"][target] = existing
            state["paths"].pop(source)
            for unused_handle, handle_entry in state["handles"].items():
                if type(handle_entry) == "dict" and handle_entry.get("kind") == "file" and handle_entry["value"].get("path") == source:
                    handle_entry["value"]["path"] = target
            return 1
        if name in ["createfilemappinga", "createfilemappingw"]:
            wide = name.endswith("w")
            opened = None if args[0] == 0xffffffff else file_handle(args[0])
            if args[0] != 0xffffffff and opened == None:
                state["last_error"] = 6
                return 0
            object_name = machine.read_cstring(args[5], encoding = "utf16le" if wide else "ascii") if args[5] else ""
            identity = object_name.lower()
            if identity and identity in state["named_mappings"]:
                state["last_error"] = 183  # ERROR_ALREADY_EXISTS
                return create_handle("mapping", state["named_mappings"][identity])
            size = (args[3] << 32) | args[4]
            path = opened["path"] if opened != None else None
            if size == 0 and path != None:
                size = len(file_data(path))
            if size <= 0 or size > maximum_file_size:
                state["last_error"] = 87
                return 0
            mapping = {"path": path, "size": size, "name": object_name, "data": b"\x00" * size if path == None else b""}
            if identity:
                state["named_mappings"][identity] = mapping
            state["last_error"] = 0
            state["file_queries"].append({"api": name, "path": path, "name": object_name, "size": size, "protect": args[2]})
            return create_handle("mapping", mapping)
        if name in ["openfilemappinga", "openfilemappingw"]:
            wide = name.endswith("w")
            object_name = machine.read_cstring(args[2], encoding = "utf16le" if wide else "ascii") if args[2] else ""
            mapping = state["named_mappings"].get(object_name.lower())
            state["file_queries"].append({"api": name, "name": object_name, "found": mapping != None, "access": args[0]})
            if mapping == None:
                state["last_error"] = 2
                return 0
            state["last_error"] = 0
            return create_handle("mapping", mapping)
        if name in ["mapviewoffile", "mapviewoffileex"]:
            entry = state["handles"].get(args[0])
            if type(entry) != "dict" or entry.get("kind") != "mapping":
                state["last_error"] = 6
                return 0
            mapping = entry["value"]
            offset = (args[2] << 32) | args[3]
            size = args[4] if args[4] else mapping["size"] - offset
            if offset < 0 or size <= 0 or size > maximum_file_size or offset + size > mapping["size"]:
                state["last_error"] = 87
                return 0
            if name == "mapviewoffileex" and args[5]:
                state["last_error"] = 487  # ERROR_INVALID_ADDRESS
                return 0
            state["file_queries"].append({"api": name, "path": mapping["path"], "offset": offset, "size": size, "access": args[1]})
            value = b""
            if mapping["path"] != None:
                data = file_data(mapping["path"])
                value = data[offset:offset + size]
            else:
                value = mapping["data"][offset:offset + size]
            address = machine.allocate(size = size, value = value, name = "file mapping")
            state["views"][address] = {"mapping": mapping, "offset": offset, "size": size}
            return address
        if name == "flushviewoffile":
            if not flush_view(machine, args[0], args[1]):
                state["last_error"] = 87
                return 0
            return 1
        if name == "unmapviewoffile":
            if not flush_view(machine, args[0]):
                state["last_error"] = 87
                return 0
            state["views"].pop(args[0])
            machine.free(args[0])
            return 1
        if name in ["deletefilea", "deletefilew"]:
            target = file_path(machine, args[0], name.endswith("w"))
            existing = state["paths"].get(target)
            record = {"api": name, "path": target, "found": existing != None}
            if existing != None and not existing.get("directory", False):
                data = entry_data(existing)
                record["size"] = len(data)
                record["sha256"] = hex(crypto.hash("sha256", data))
            state["file_queries"].append(record)
            if existing == None or existing.get("directory", False):
                state["last_error"] = 2  # ERROR_FILE_NOT_FOUND
                return 0
            state["paths"].pop(target)
            state["last_error"] = 0
            return 1
        if name in ["getsystemdefaultlangid", "getuserdefaultlangid", "getsystemdefaultuilanguage", "getuserdefaultuilanguage"]:
            return 0x0409
        if name in ["getsystemdefaultlcid", "getuserdefaultlcid"]:
            return 0x0409
        if name in ["getlocaleinfoa", "getlocaleinfow"]:
            wide = name.endswith("w")
            values = {
                0x0001: "0409",                    # LOCALE_ILANGUAGE
                0x0002: "English (United States)", # LOCALE_SLANGUAGE
                0x0006: "United States",           # LOCALE_SCOUNTRY
                0x000b: "437",                     # LOCALE_IDEFAULTCODEPAGE
                0x1001: "English (United States)", # LOCALE_SENGLANGUAGE
                0x1002: "United States",           # LOCALE_SENGCOUNTRY
                0x1004: "1252",                    # LOCALE_IDEFAULTANSICODEPAGE
            }
            value = values.get(args[1] & 0xffff, "")
            required = len(value) + 1
            if not args[2] or args[3] == 0:
                return required
            if args[3] < required:
                state["last_error"] = 122
                return 0
            _write_string(machine, args[2], value, wide, args[3])
            return required
        if name == "getacp":
            return 1252
        if name == "getoemcp":
            return 437
        if name == "getcpinfo":
            if not args[1]:
                state["last_error"] = 87
                return 0
            info = binary.builder(capacity = 20)
            info.u32le(1)
            info.u8(0x3f)
            info.u8(0)
            info.reserve(12)
            info.u16le(0)
            machine.write(args[1], info.bytes())
            return 1
        if name in ["getdateformata", "getdateformatw"]:
            wide = name.endswith("w")
            if args[2]:
                fields = binary.cursor(machine.read(args[2], 16))
                year = fields.u16le()
                month = fields.u16le()
                day_of_week = fields.u16le()
                day = fields.u16le()
            else:
                year, month, day_of_week, day = 2000, 1, 6, 1
            if month < 1 or month > 12 or day < 1 or day > 31 or day_of_week > 6:
                state["last_error"] = 87
                return 0
            pattern = machine.read_cstring(args[3], encoding = "utf16le" if wide else "ascii") if args[3] else ("dddd, MMMM d, yyyy" if args[1] & 0x2 else "M/d/yyyy")
            value = date_text(pattern, year, month, day, day_of_week)
            required = len(value) + 1
            if not args[4] or args[5] == 0:
                return required
            if args[5] < required:
                state["last_error"] = 122
                return 0
            _write_string(machine, args[4], value, wide, args[5])
            return required
        if name in ["gettimeformata", "gettimeformatw"]:
            wide = name.endswith("w")
            if args[2]:
                fields = binary.cursor(machine.read(args[2], 16))
                fields.skip(8)
                hour = fields.u16le()
                minute = fields.u16le()
                second = fields.u16le()
            else:
                hour, minute, second = 0, 0, 0
            if hour > 23 or minute > 59 or second > 59:
                state["last_error"] = 87
                return 0
            if args[3]:
                pattern = machine.read_cstring(args[3], encoding = "utf16le" if wide else "ascii")
            else:
                pattern = "H:mm:ss" if args[1] & 0x8 else "h:mm:ss tt"
                if args[1] & 0x1:
                    pattern = "H" if args[1] & 0x8 else "h tt"
                elif args[1] & 0x2:
                    pattern = "H:mm" if args[1] & 0x8 else "h:mm tt"
                if args[1] & 0x4:
                    pattern = pattern.replace(" tt", "")
            value = time_text(pattern, hour, minute, second)
            required = len(value) + 1
            if not args[4] or args[5] == 0:
                return required
            if args[5] < required:
                state["last_error"] = 122
                return 0
            _write_string(machine, args[4], value, wide, args[5])
            return required
        if name in ["getstringtypea", "getstringtypew", "getstringtypeexa", "getstringtypeexw"]:
            wide = name.endswith("w")
            has_locale = name.startswith("getstringtypeex") or not wide
            info_type = args[1] if has_locale else args[0]
            source = args[2] if has_locale else args[1]
            requested = args[3] if has_locale else args[2]
            output = args[4] if has_locale else args[3]
            if not source or not output:
                state["last_error"] = 87
                return 0
            if requested == 0xffffffff:
                value = machine.read_cstring(source, encoding = "utf16le" if wide else "ascii")
                data = binary.encode(value, encoding = "utf16le" if wide else "ascii", nul = True)
                count = len(data) // (2 if wide else 1)
            else:
                count = requested
                if count > 65536:
                    state["last_error"] = 87
                    return 0
                data = machine.read(source, count * (2 if wide else 1))
            cursor = binary.cursor(data)
            classes = binary.builder(capacity = count * 2)
            for unused in range(count):
                code = cursor.u16le() if wide else cursor.u8()
                classes.u16le(character_type(code) if info_type == 1 else 0)
            machine.write(output, classes.bytes())
            return 1
        if name in ["lcmapstringa", "lcmapstringw"]:
            wide = name.endswith("w")
            source = args[2]
            requested = args[3]
            output = args[4]
            capacity = args[5]
            width = 2 if wide else 1
            if not source:
                state["last_error"] = 87
                return 0
            if requested == 0xffffffff:
                value = machine.read_cstring(source, encoding = "utf16le" if wide else "ascii")
                data = binary.encode(value, encoding = "utf16le" if wide else "ascii", nul = True)
                count = len(data) // width
            else:
                count = requested
                if count > 65536:
                    state["last_error"] = 87
                    return 0
                data = machine.read(source, count * width)
            cursor = binary.cursor(data)
            mapped = binary.builder(capacity = count * width)
            for unused in range(count):
                code = cursor.u16le() if wide else cursor.u8()
                if args[1] & 0x100 and code >= 65 and code <= 90:
                    code += 32
                elif args[1] & 0x200 and code >= 97 and code <= 122:
                    code -= 32
                if wide:
                    mapped.u16le(code)
                else:
                    mapped.u8(code)
            if output == 0:
                return count
            if capacity < count:
                state["last_error"] = 122
                return 0
            machine.write(output, mapped.bytes())
            return count
        if name == "multibytetowidechar":
            if not args[2]:
                state["last_error"] = 87
                return 0
            source = terminated_data(machine, args[2], 1) if args[3] == 0xffffffff else machine.read(args[2], args[3])
            converted = binary.builder(capacity = len(source) * 2)
            cursor = binary.cursor(source)
            for unused in range(len(source)):
                converted.u16le(cursor.u8())
            required = len(source)
            if args[4] == 0:
                return required
            if args[5] < required:
                state["last_error"] = 122
                return 0
            machine.write(args[4], converted.bytes())
            return required
        if name == "widechartomultibyte":
            if not args[2]:
                state["last_error"] = 87
                return 0
            source = terminated_data(machine, args[2], 2) if args[3] == 0xffffffff else machine.read(args[2], args[3] * 2)
            count = len(source) // 2
            converted = binary.builder(capacity = count)
            cursor = binary.cursor(source)
            used_default = False
            default = machine.read_u8(args[6]) if args[6] else 0x3f
            for unused in range(count):
                code = cursor.u16le()
                if code <= 0xff:
                    converted.u8(code)
                else:
                    converted.u8(default)
                    used_default = True
            if args[7]:
                machine.write_u32le(args[7], 1 if used_default else 0)
            if args[4] == 0:
                return count
            if args[5] < count:
                state["last_error"] = 122
                return 0
            machine.write(args[4], converted.bytes())
            return count
        if name == "getsystemtimeasfiletime":
            builder = binary.builder(capacity = 8)
            builder.u64le(system_time_ticks)
            machine.write(args[0], builder.bytes())
            return None
        if name == "getsystemtimeadjustment":
            if not args[0] or not args[1] or not args[2]:
                state["last_error"] = 87
                return 0
            machine.write_u32le(args[0], state["time_adjustment"])
            machine.write_u32le(args[1], state["time_increment"])
            machine.write_u32le(args[2], 1 if state["time_adjustment_disabled"] else 0)
            state["last_error"] = 0
            return 1
        if name == "systemtimetofiletime":
            if not args[0] or not args[1]:
                state["last_error"] = 87
                return 0
            fields = binary.cursor(machine.read(args[0], 16))
            year = fields.u16le()
            month = fields.u16le()
            fields.u16le()  # Day of week is derived and is not an input constraint.
            day = fields.u16le()
            ticks = _filetime_ticks(year, month, day, fields.u16le(), fields.u16le(), fields.u16le(), fields.u16le())
            if ticks == None:
                state["last_error"] = 87
                return 0
            output = binary.builder(capacity = 8)
            output.u64le(ticks)
            machine.write(args[1], output.bytes())
            return 1
        if name in ["filetimetolocalfiletime", "localfiletimetofiletime"]:
            if not args[0] or not args[1]:
                state["last_error"] = 87
                return 0
            # The deterministic process environment reports
            # TIME_ZONE_ID_UNKNOWN with a zero bias, so UTC and local
            # FILETIME values have the same representation.
            machine.write(args[1], machine.read(args[0], 8))
            return 1
        if name == "filetimetosystemtime":
            if not args[0] or not args[1]:
                state["last_error"] = 87
                return 0
            fields = _filetime_fields(machine.read_u64le(args[0]))
            if fields == None:
                state["last_error"] = 87
                return 0
            output = binary.builder(capacity = 16)
            for field in fields:
                output.u16le(field)
            machine.write(args[1], output.bytes())
            return 1
        if name == "getsysteminfo":
            info = binary.builder(capacity = 36)
            info.u16le(0)  # PROCESSOR_ARCHITECTURE_INTEL
            info.u16le(0)
            info.u32le(4096)
            info.u32le(0x10000)
            info.u32le(0x7ffeffff)
            info.u32le(1)
            info.u32le(1)
            info.u32le(586)
            info.u32le(0x10000)
            info.u16le(6)
            info.u16le(0)
            machine.write(args[0], info.bytes())
            return None
        if name == "isdebuggerpresent":
            return 0
        if name == "isprocessorfeaturepresent":
            return 1 if args[0] in processor_features else 0
        if name in ["globalmemorystatus", "globalmemorystatusex"]:
            if name == "globalmemorystatus":
                if not args[0]:
                    return None
                status = binary.builder(capacity = 32)
                for value in [32, 25, 512 << 20, 384 << 20, 1024 << 20, 768 << 20, 2 << 30, 1536 << 20]:
                    status.u32le(value)
                machine.write(args[0], status.bytes())
                return None
            if not args[0] or machine.read_u32le(args[0]) != 64:
                state["last_error"] = 87  # ERROR_INVALID_PARAMETER
                return 0
            total_physical = 512 << 20
            available_physical = 384 << 20
            total_page = 1024 << 20
            available_page = 768 << 20
            total_virtual = 2 << 30
            available_virtual = 1536 << 20
            status = binary.builder(capacity = 64)
            status.u32le(64)
            status.u32le(25)
            for value in [total_physical, available_physical, total_page, available_page, total_virtual, available_virtual, 0]:
                status.u64le(value)
            machine.write(args[0], status.bytes())
            return 1
        if name in ["getstartupinfoa", "getstartupinfow"]:
            # STARTUPINFOA/W have the same fixed 32-bit layout; pointed-to
            # strings are absent in the deterministic registration process.
            machine.write(args[0], b"\x00" * 68)
            machine.write_u32le(args[0], 68)
            return None
        if name == "getstdhandle":
            handle = state["standard_handles"].get(args[0])
            if handle == None:
                handle = create_handle("standard", {"selector": args[0]})
                state["standard_handles"][args[0]] = handle
            return handle
        if name == "getfiletype":
            handle = state["handles"].get(args[0])
            if type(handle) == "dict" and handle.get("kind") == "standard":
                return 2  # FILE_TYPE_CHAR
            if type(handle) == "dict" and handle.get("kind") == "file":
                state["last_error"] = 0
                return 1  # FILE_TYPE_DISK
            state["last_error"] = 6
            return 0
        if name == "sethandlecount":
            return args[0]
        if name == "seterrormode":
            previous = state.get("error_mode", 0)
            state["error_mode"] = args[0]
            return previous
        if name == "setconsolectrlhandler":
            state.setdefault("console_handlers", {})[args[0]] = args[1] != 0
            return 1
        if name == "setprocessshutdownparameters":
            state["shutdown_parameters"] = {"level": args[0], "flags": args[1]}
            return 1
        if name == "setsystemtimeadjustment":
            state["time_adjustment"] = args[0]
            state["time_adjustment_disabled"] = bool(args[1])
            state["last_error"] = 0
            return 1
        if name in ["getlocaltime", "getsystemtime"]:
            builder = binary.builder(capacity = 16)
            for value in system_time_structure:
                builder.u16le(value)
            machine.write(args[0], builder.bytes())
            return None
        if name == "gettimezoneinformation":
            if args[0]:
                machine.write(args[0], b"\x00" * 172)
            return 0  # TIME_ZONE_ID_UNKNOWN
        if name in ["getsystemdirectorya", "getsystemdirectoryw"]:
            return _write_string(machine, args[0], system_directory, name.endswith("w"), args[1])
        if name in ["getwindowsdirectorya", "getwindowsdirectoryw"]:
            return _write_string(machine, args[0], windows_directory, name.endswith("w"), args[1])
        if name in ["getversionexa", "getversionexw"]:
            size = machine.read_u32le(args[0])
            if size < 20:
                return 0
            machine.write(args[0], b"\x00" * size)
            machine.write_u32le(args[0], size)
            machine.write_u32le(args[0] + 4, version_major)
            machine.write_u32le(args[0] + 8, version_minor)
            machine.write_u32le(args[0] + 12, version_build)
            machine.write_u32le(args[0] + 16, platform_id)
            if size > 20:
                wide = name.endswith("w")
                width = 2 if wide else 1
                _write_string(machine, args[0] + 20, service_pack, wide, min(128, (size - 20) // width))
                extension = 20 + 128 * width
                if size >= extension + 8:
                    builder = binary.builder(capacity = 8)
                    builder.u16le(service_pack_major)
                    builder.u16le(service_pack_minor)
                    builder.u16le(0)
                    builder.u8(product_type_number)
                    builder.u8(0)
                    machine.write(args[0] + extension, builder.bytes())
            return 1
        if name == "getversion":
            legacy_platform = 0x80000000 if platform_id == 1 else 0
            return legacy_platform | ((version_build & 0x7fff) << 16) | (version_minor << 8) | version_major
        if name == "getprocessversion":
            return (version_major << 16) | version_minor
        if name == "versetconditionmask":
            mask = args[0] | (args[1] << 32)
            result = _version_condition_mask(mask, args[2], args[3])
            machine.set_register("edx", (result >> 32) & 0xffffffff)
            return result & 0xffffffff
        if name in ["verifyversioninfoa", "verifyversioninfow"]:
            if not args[0]:
                state["last_error"] = 87
                return 0
            wide = name.endswith("w")
            service_pack_offset = 276 if wide else 148
            requested = {
                0x00000001: machine.read_u32le(args[0] + 8),
                0x00000002: machine.read_u32le(args[0] + 4),
                0x00000004: machine.read_u32le(args[0] + 12),
                0x00000008: machine.read_u32le(args[0] + 16),
                0x00000010: machine.read_u16le(args[0] + service_pack_offset + 2),
                0x00000020: machine.read_u16le(args[0] + service_pack_offset),
                0x00000040: machine.read_u16le(args[0] + service_pack_offset + 4),
                0x00000080: machine.read_u8(args[0] + service_pack_offset + 6),
            }
            actual = {
                0x00000001: version_minor,
                0x00000002: version_major,
                0x00000004: version_build,
                0x00000008: platform_id,
                0x00000010: service_pack_minor,
                0x00000020: service_pack_major,
                0x00000040: suite_mask,
                0x00000080: product_type_number,
            }
            condition_mask = args[2] | (args[3] << 32)
            for version_type, shift in _VERSION_CONDITION_SHIFTS.items():
                if args[1] & version_type and not _version_condition_satisfied(
                        actual[version_type],
                        requested[version_type],
                        (condition_mask >> shift) & 7):
                    state["last_error"] = 1150  # ERROR_OLD_WIN_VERSION
                    return 0
            state["last_error"] = 0
            return 1
        if name in ["getvolumeinformationa", "getvolumeinformationw"]:
            if not args[0]:
                state["last_error"] = 87
                return 0
            wide = name.endswith("w")
            root = file_path(machine, args[0], wide)
            drive = root[:2].upper() if len(root) >= 2 and root[1] == ":" else ""
            facts = volume_facts.get(drive, {})
            label = str(facts.get("label", "System"))
            filesystem_name = str(facts.get("filesystem", "NTFS"))
            if args[1] and args[2] <= len(label):
                state["last_error"] = 122
                return 0
            if args[6] and args[7] <= len(filesystem_name):
                state["last_error"] = 122
                return 0
            if args[1]:
                _write_string(machine, args[1], label, wide, args[2])
            if args[3]:
                machine.write_u32le(args[3], int(facts.get("serial", 0x54525854)) & 0xffffffff)
            if args[4]:
                machine.write_u32le(args[4], int(facts.get("max_component_length", 255)))
            if args[5]:
                # Case preservation, Unicode names, persistent ACLs,
                # compression, quotas, sparse files, reparse points, object
                # IDs, and encryption are the NT5 NTFS capability surface.
                machine.write_u32le(args[5], int(facts.get("flags", 0x000300ff)))
            if args[6]:
                _write_string(machine, args[6], filesystem_name, wide, args[7])
            state["last_error"] = 0
            return 1
        if name in ["getdiskfreespacea", "getdiskfreespacew"]:
            # Registration runs against a bounded in-memory filesystem. Report
            # stable NTFS-like geometry with enough room for setup decisions.
            if not all(args[1:]):
                state["last_error"] = 87  # ERROR_INVALID_PARAMETER
                return 0
            for address, value in zip(args[1:], [8, 512, 1 << 18, 1 << 20]):
                machine.write_u32le(address, value)
            state["last_error"] = 0
            return 1
        if name in ["queryperformancecounter", "queryperformancefrequency"]:
            builder = binary.builder(capacity = 8)
            builder.u64le(0 if name.endswith("counter") else 10000000)
            machine.write(args[0], builder.bytes())
            return 1
        if name in ["writeprivateprofilesectiona", "writeprivateprofilesectionw", "writeprivateprofilestringa", "writeprivateprofilestringw"]:
            return 1
        if name in ["getprivateprofilesectiona", "getprivateprofilesectionw"]:
            wide = name.endswith("w")
            section_name = machine.read_cstring(args[0], encoding = "utf16le" if wide else "ascii") if args[0] else ""
            path, contents = profile(machine, args[3], wide)
            section = contents["sections"].get(section_name.lower())
            values = [] if section == None else [item["line"] for item in section["items"]]
            state["profile_queries"].append({"api": name, "path": path, "section": section_name, "found": section != None})
            return write_profile_list(machine, args[1], values, wide, args[2])
        if name in ["getprivateprofilesectionnamesa", "getprivateprofilesectionnamesw"]:
            wide = name.endswith("w")
            path, contents = profile(machine, args[2], wide)
            state["profile_queries"].append({"api": name, "path": path, "found": bool(contents["order"])})
            return write_profile_list(machine, args[0], contents["order"], wide, args[1])
        if name in ["getprivateprofileinta", "getprivateprofileintw"]:
            wide = name.endswith("w")
            section_name = machine.read_cstring(args[0], encoding = "utf16le" if wide else "ascii") if args[0] else ""
            key_name = machine.read_cstring(args[1], encoding = "utf16le" if wide else "ascii") if args[1] else ""
            path, contents = profile(machine, args[3], wide)
            section = contents["sections"].get(section_name.lower())
            value = None if section == None else section["values"].get(key_name.lower())
            parsed = _parse_c_integer(value, 10) if value != None else {"value": 0, "consumed": 0}
            found = parsed["consumed"] != 0
            state["profile_queries"].append({"api": name, "path": path, "section": section_name, "key": key_name, "found": found})
            return parsed["value"] & 0xffffffff if found else args[2]
        if name in ["getprivateprofilestringa", "getprivateprofilestringw"]:
            wide = name.endswith("w")
            default = machine.read_cstring(args[2], encoding = "utf16le" if wide else "ascii") if args[2] else ""
            section_name = machine.read_cstring(args[0], encoding = "utf16le" if wide else "ascii") if args[0] else ""
            key_name = machine.read_cstring(args[1], encoding = "utf16le" if wide else "ascii") if args[1] else ""
            path, contents = profile(machine, args[5], wide)
            section = contents["sections"].get(section_name.lower())
            state["profile_queries"].append({"api": name, "path": path, "section": section_name, "key": key_name, "found": section != None and (not key_name or key_name.lower() in section["values"])})
            if not args[0]:
                return write_profile_list(machine, args[3], contents["order"], wide, args[4])
            if not args[1]:
                keys = [] if section == None else [item["key"] for item in section["items"]]
                return write_profile_list(machine, args[3], keys, wide, args[4])
            value = default if section == None else section["values"].get(key_name.lower(), default)
            return _write_string(machine, args[3], value, wide, args[4])
        if name in ["setfileattributesa", "setfileattributesw"]:
            return 1
        if name in ["getmodulehandleexa", "getmodulehandleexw"]:
            flags, module, output = args
            if not output or (flags & 0x3) == 0x3:
                state["last_error"] = 87  # ERROR_INVALID_PARAMETER
                return 0
            loaded = None
            if flags & 0x4:  # GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                for candidate in machine.modules:
                    if candidate.base <= module and (loaded == None or candidate.base > loaded["handle"]):
                        loaded = {"name": candidate.name, "handle": candidate.base}
            elif module == 0:
                loaded = find_module(machine, handle = state["main"])
            else:
                wide = name.endswith("w")
                requested = machine.read_cstring(module, encoding = "utf16le" if wide else "ascii")
                loaded = find_module(machine, name = requested)
            if loaded == None:
                state["last_error"] = 126  # ERROR_MOD_NOT_FOUND
                return 0
            machine.write_u32le(output, loaded["handle"])
            return 1
        if name in ["getmodulehandlea", "getmodulehandlew", "loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw"]:
            if name.startswith("getmodulehandle") and args[0] == 0:
                return state["main"]
            wide = name.endswith("w")
            requested = module_name(machine.read_cstring(args[0], encoding = "utf16le" if wide else "ascii"))
            loaded = find_module(machine, name = requested) if name.startswith("getmodulehandle") else load_module(machine, requested, name)
            if name.startswith("getmodulehandle"):
                state["module_queries"].append({"api": name, "module": requested, "found": loaded != None})
            state["last_error"] = 0 if loaded != None else 126
            return loaded["handle"] if loaded != None else 0
        if name == "resolvedelayloadedapi":
            parent, descriptor, unused_dll_hook, unused_system_hook, thunk, flags = args
            if not parent or not descriptor or not thunk or flags:
                state["last_error"] = 87  # ERROR_INVALID_PARAMETER
                return 0
            attributes = machine.read_u32le(descriptor)
            if attributes & ~1:
                state["last_error"] = 87
                return 0
            relative = bool(attributes & 1)
            def address(field):
                return (parent + field) & 0xffffffff if relative and field else field
            dll_name = address(machine.read_u32le(descriptor + 4))
            module_slot = address(machine.read_u32le(descriptor + 8))
            iat = address(machine.read_u32le(descriptor + 12))
            names = address(machine.read_u32le(descriptor + 16))
            if not dll_name or not module_slot or not iat or not names or thunk < iat or (thunk - iat) & 3:
                state["last_error"] = 87
                return 0
            index = (thunk - iat) // 4
            if index >= 65536:
                state["last_error"] = 87
                return 0
            requested = machine.read_cstring(dll_name, maximum = 260)
            loaded = load_module(machine, requested, name)
            if loaded == None:
                state["last_error"] = 126  # ERROR_MOD_NOT_FOUND
                return 0
            lookup = machine.read_u32le(names + index * 4)
            if lookup & 0x80000000:
                procedure = "#" + str(lookup & 0xffff)
                resolved = machine.resolve_export(loaded["name"], ordinal = lookup & 0xffff)
            else:
                import_name = address(lookup)
                if not import_name:
                    state["last_error"] = 127  # ERROR_PROC_NOT_FOUND
                    return 0
                procedure = machine.read_cstring(import_name + 2, maximum = 4096)
                resolved = machine.resolve_export(loaded["name"], name = procedure)
            state["procedure_queries"].append({"module": loaded["name"], "procedure": procedure, "found": resolved != 0})
            if not resolved:
                state["last_error"] = 127
                return 0
            machine.write_u32le(module_slot, loaded["handle"])
            machine.write_u32le(thunk, resolved)
            state["last_error"] = 0
            return resolved
        if name == "ldrloaddll":
            if not args[2] or not args[3]:
                return 0xc000000d
            descriptor = binary.cursor(machine.read(args[2], 8))
            length = descriptor.u16le()
            descriptor.u16le()
            address = descriptor.u32le()
            requested = module_name(binary.text(machine.read(address, length), encoding = "utf16le")) if address else ""
            loaded = find_module(machine, name = requested)
            if loaded == None and on_module_load != None:
                handle = on_module_load(requested)
                if handle:
                    state["modules"][requested] = handle
                    state["handles"][handle] = requested
                    loaded = find_module(machine, name = requested)
            state["module_queries"].append({"api": name, "module": requested, "found": loaded != None})
            if loaded == None:
                return 0xc0000135  # STATUS_DLL_NOT_FOUND
            machine.write_u32le(args[3], loaded["handle"])
            return 0
        if name == "getprocaddress":
            loaded = find_module(machine, handle = args[0])
            if loaded == None:
                return 0
            if args[1] < 65536:
                procedure = "#" + str(args[1])
                address = machine.resolve_export(loaded["name"], ordinal = args[1])
            else:
                procedure = machine.read_cstring(args[1])
                address = machine.resolve_export(loaded["name"], name = procedure)
            state["procedure_queries"].append({"module": loaded["name"], "procedure": procedure, "found": address != 0})
            return address
        if name == "setlasterror":
            state["last_error"] = args[0]
            return None
        if name == "setunhandledexceptionfilter":
            previous = state["unhandled_exception_filter"]
            state["unhandled_exception_filter"] = args[0]
            return previous
        if name == "unhandledexceptionfilter":
            return 0
        if name == "getlasterror":
            return state["last_error"]
        if name == "getcurrentactctx":
            if not args[0]:
                state["last_error"] = 87
                return 0
            if not state["current_actctx"]:
                state["current_actctx"] = create_handle("actctx", {"default": True})
            state["actctx_refs"] += 1
            machine.write_u32le(args[0], state["current_actctx"])
            state["last_error"] = 0
            return 1
        if name == "addrefactctx":
            if args[0] == state["current_actctx"]:
                state["actctx_refs"] += 1
            return None
        if name == "releaseactctx":
            if args[0] == state["current_actctx"] and state["actctx_refs"] > 0:
                state["actctx_refs"] -= 1
            return None
        if name == "tlsalloc":
            index = state["next_tls"]
            state["next_tls"] = index + 1
            state["tls"][index] = 0
            return index
        if name == "tlsfree":
            state["tls"][args[0]] = None
            return 1
        if name == "tlsgetvalue":
            return state["tls"].get(args[0], 0) or 0
        if name == "tlssetvalue":
            state["tls"][args[0]] = args[1]
            return 1
        if name in ["closehandle", "ntclose"]:
            state["handles"].pop(args[0], None)
            return 0 if name == "ntclose" else 1
        if name in ["heapfree", "rtlfreeheap"]:
            if args[0] not in state["heaps"]:
                state["last_error"] = 6
                return 0
            if args[2] == 0:
                return 1
            allocation = state["allocations"].get(args[2])
            if allocation == None or allocation["heap"] != args[0]:
                state["last_error"] = 87  # ERROR_INVALID_PARAMETER
                return 0
            state["allocations"].pop(args[2])
            machine.free(args[2])
            return 1
        if name in ["disablethreadlibrarycalls", "freelibrary"]:
            return 1
        if name in ["initializecriticalsection", "initializecriticalsectionandspincount", "rtlinitializecriticalsection", "rtlinitializecriticalsectionandspincount"]:
            machine.write(args[0], b"\x00" * 24)
            state["critical_sections"][args[0]] = {"owner": None, "depth": 0}
            return 0 if name.startswith("rtl") else 1
        if name == "rtlinitializeresource":
            if args[0]:
                # RTL_RESOURCE is opaque to callers. Keep deterministic bytes
                # for code that embeds it while tracking lock state separately.
                machine.write(args[0], b"\x00" * 56)
                state["resources"][args[0]] = {"exclusive": 0, "shared": 0}
            return None
        if name == "rtldeleteresource":
            state["resources"].pop(args[0], None)
            return None
        if name in ["rtlacquireresourceexclusive", "rtlacquireresourceshared"]:
            resource = state["resources"].get(args[0])
            if resource == None:
                return 0
            if name == "rtlacquireresourceexclusive":
                resource["exclusive"] += 1
            else:
                resource["shared"] += 1
            return 1
        if name == "rtlreleaseresource":
            resource = state["resources"].get(args[0])
            if resource != None:
                if resource["exclusive"]:
                    resource["exclusive"] -= 1
                elif resource["shared"]:
                    resource["shared"] -= 1
            return None
        if name == "deletecriticalsection":
            state["critical_sections"].pop(args[0], None)
            return None
        if name == "entercriticalsection":
            enter_critical_section(machine, args[0], True)
            return None
        if name == "leavecriticalsection":
            leave_critical_section(machine, args[0])
            return None
        if name == "tryentercriticalsection":
            return 1 if enter_critical_section(machine, args[0], False) else 0
        if name == "isdbcsleadbyte":
            return 0
        if name == "isbadcodeptr":
            # Executable callbacks in this environment come from mapped target
            # images or bounded semantic exports; null is never callable.
            return 1 if args[0] == 0 else 0
        if name == "iswow64process":
            machine.write_u32le(args[1], 0)
            return 1
        if name == "rtldeletecriticalsection":
            state["critical_sections"].pop(args[0], None)
            return 0
        if name == "rtlentercriticalsection":
            enter_critical_section(machine, args[0], True)
            return 0
        if name == "rtlleavecriticalsection":
            leave_critical_section(machine, args[0])
            return 0
        if name == "rtlgetntproducttype":
            machine.write_u32le(args[0], product_type_number)
            return 1
        if name == "rtlgetntversionnumbers":
            if args[0]:
                machine.write_u32le(args[0], version_major)
            if args[1]:
                machine.write_u32le(args[1], version_minor)
            if args[2]:
                machine.write_u32le(args[2], version_build | 0xf0000000)
            return None
        if name in ["ntqueryinformationthread", "ntsetinformationthread"]:
            handle, information_class, output, size = args[:4]
            thread_id = thread_id_for_handle(handle)
            state["thread_queries"].append({
                "api": name,
                "thread": thread_id,
                "class": information_class,
                "size": size,
            })
            if thread_id == None:
                return 0xc0000008  # STATUS_INVALID_HANDLE
            if information_class not in [22, 24]:  # ThreadIoPriority, ThreadPagePriority
                return 0xc0000003  # STATUS_INVALID_INFO_CLASS
            priorities = state["thread_io_priorities"] if information_class == 22 else state["thread_page_priorities"]
            default_priority = 2 if information_class == 22 else 5
            if name == "ntqueryinformationthread":
                if args[4]:
                    machine.write_u32le(args[4], 4)
                if size < 4:
                    return 0xc0000004  # STATUS_INFO_LENGTH_MISMATCH
                if not output:
                    return 0xc000000d  # STATUS_INVALID_PARAMETER
                machine.write_u32le(output, priorities.get(thread_id, default_priority))
                return 0
            if size != 4 or not output:
                return 0xc000000d
            priority = machine.read_u32le(output)
            if information_class == 22 and priority > 3:
                return 0xc000000d
            if information_class == 24 and (priority < 1 or priority > 5):
                return 0xc000000d
            priorities[thread_id] = priority
            return 0
        if name == "rtlntstatustodoserror":
            # Keep the common native-to-Win32 mappings deterministic. Unknown
            # status values use ERROR_MR_MID_NOT_FOUND, matching the API's
            # contract and allowing callers to preserve the original status.
            return {
                0x00000000: 0,
                0xc0000001: 31,    # ERROR_GEN_FAILURE
                0xc0000002: 1,     # ERROR_INVALID_FUNCTION
                0xc0000003: 87,    # ERROR_INVALID_PARAMETER
                0xc0000004: 24,    # ERROR_BAD_LENGTH
                0xc0000005: 998,   # ERROR_NOACCESS
                0xc0000008: 6,     # ERROR_INVALID_HANDLE
                0xc000000d: 87,    # ERROR_INVALID_PARAMETER
                0xc0000017: 8,     # ERROR_NOT_ENOUGH_MEMORY
                0xc0000022: 5,     # ERROR_ACCESS_DENIED
                0xc0000023: 122,   # ERROR_INSUFFICIENT_BUFFER
                0xc0000034: 2,     # ERROR_FILE_NOT_FOUND
                0xc0000035: 183,   # ERROR_ALREADY_EXISTS
                0xc000003a: 3,     # ERROR_PATH_NOT_FOUND
                0xc000007a: 127,   # ERROR_PROC_NOT_FOUND
                0xc0000135: 126,   # ERROR_MOD_NOT_FOUND
                0xc0000142: 1114,  # ERROR_DLL_INIT_FAILED
                0xc0000225: 1168,  # ERROR_NOT_FOUND
            }.get(args[0], 317)  # ERROR_MR_MID_NOT_FOUND
        if name == "rtlimagentheader":
            base = args[0]
            if base == 0:
                return 0
            header = machine.read(base, 0x40)
            cursor = binary.cursor(header)
            if cursor.u16le() != 0x5a4d:
                return 0
            cursor.seek(0x3c)
            offset = cursor.u32le()
            return base + offset if machine.read(base + offset, 4) == b"PE\x00\x00" else 0
        if name == "rtlvalidateprocessheaps":
            return 1
        if name == "rtltryentercriticalsection":
            return 1 if enter_critical_section(machine, args[0], False) else 0
        if name == "rtlmovememory":
            if args[0] and args[1] and args[2]:
                machine.write(args[0], machine.read(args[1], args[2]))
            return None
        if name == "rtlfillmemory":
            if args[0] and args[1]:
                value = binary.builder(capacity = args[1])
                for unused in range(args[1]):
                    value.u8(args[2] & 0xff)
                machine.write(args[0], value.bytes())
            return None
        if name == "rtlzeromemory":
            if args[0] and args[1]:
                machine.write(args[0], b"\x00" * args[1])
            return None
        if name == "globalfree":
            if args[0] not in state["global_allocations"]:
                state["last_error"] = 6  # ERROR_INVALID_HANDLE
                return args[0]
            state["global_allocations"].pop(args[0])
            machine.free(args[0])
            state["last_error"] = 0
            return 0
        if name == "localfree":
            if args[0] not in state["local_allocations"]:
                state["last_error"] = 6
                return args[0]
            state["local_allocations"].pop(args[0])
            machine.free(args[0])
            state["last_error"] = 0
            return 0
        if name == "localsize":
            allocation = state["local_allocations"].get(args[0])
            if allocation == None:
                state["last_error"] = 6
                return 0
            state["last_error"] = 0
            return allocation
        if name == "globallock":
            allocation = state["global_allocations"].get(args[0])
            if allocation == None:
                state["last_error"] = 6
                return 0
            allocation["locks"] += 1
            state["last_error"] = 0
            return args[0]
        if name == "globalsize":
            allocation = state["global_allocations"].get(args[0])
            if allocation == None:
                state["last_error"] = 6
                return 0
            state["last_error"] = 0
            return allocation["size"]
        if name == "globalunlock":
            allocation = state["global_allocations"].get(args[0])
            if allocation == None:
                state["last_error"] = 6
                return 0
            if allocation["locks"] > 0:
                allocation["locks"] -= 1
            state["last_error"] = 0
            return 1 if allocation["locks"] > 0 else 0
        if name in ["formatmessagea", "formatmessagew"]:
            wide = name.endswith("w")
            flags = args[0]
            value = None
            if flags & 0x400 and args[1]:  # FORMAT_MESSAGE_FROM_STRING
                value = machine.read_cstring(args[1], encoding = "utf16le" if wide else "ascii")
            elif flags & (0x800 | 0x1000):  # FROM_HMODULE or FROM_SYSTEM
                lookup = state.get("message_lookup")
                if lookup != None:
                    value = lookup(args[1] if flags & 0x800 else 0, args[2], args[3])
            if value == None:
                state["last_error"] = 317  # ERROR_MR_MID_NOT_FOUND
                return 0
            data = _encoded(value, wide)
            if flags & 0x100:  # FORMAT_MESSAGE_ALLOCATE_BUFFER
                output = machine.allocate(size = len(data), value = data, name = "FormatMessage")
                state["local_allocations"][output] = len(data)
                machine.write_u32le(args[4], output)
            elif not args[4] or args[5] <= len(value):
                state["last_error"] = 122  # ERROR_INSUFFICIENT_BUFFER
                return 0
            else:
                machine.write(args[4], data)
            state["last_error"] = 0
            return len(value)
        if name in ["heapalloc", "rtlallocateheap"]:
            if args[0] not in state["heaps"]:
                state["last_error"] = 6
                return 0
            address = machine.allocate(size = max(1, args[2]), name = name)
            state["allocations"][address] = {"heap": args[0], "size": args[2]}
            return address
        if name in ["heaprealloc", "rtlreallocateheap"]:
            if args[0] not in state["heaps"]:
                state["last_error"] = 6
                return 0
            previous = state["allocations"].get(args[2])
            if previous == None or previous["heap"] != args[0]:
                state["last_error"] = 87
                return 0
            address = machine.allocate(size = max(1, args[3]), name = name)
            if previous["size"] and args[3]:
                copied = min(previous["size"], args[3])
                machine.write(address, machine.read(args[2], copied))
            state["allocations"].pop(args[2])
            machine.free(args[2])
            state["allocations"][address] = {"heap": args[0], "size": args[3]}
            return address
        if name in ["heapsize", "rtlsizeheap"]:
            allocation = state["allocations"].get(args[2])
            if args[0] not in state["heaps"] or allocation == None or allocation["heap"] != args[0]:
                state["last_error"] = 87
                return 0xffffffff
            return allocation["size"]
        if name == "heapvalidate":
            if args[0] not in state["heaps"]:
                return 0
            if args[2] == 0:
                return 1
            allocation = state["allocations"].get(args[2])
            return 1 if allocation != None and allocation["heap"] == args[0] else 0
        if name == "heapcompact":
            return 0 if args[0] not in state["heaps"] else 1
        if name == "heapwalk":
            state["last_error"] = 259  # ERROR_NO_MORE_ITEMS
            return 0
        if name == "globalalloc":
            address = machine.allocate(size = max(1, args[1]), name = name)
            state["global_allocations"][address] = {"size": args[1], "flags": args[0], "locks": 0}
            return address
        if name == "localalloc":
            address = machine.allocate(size = max(1, args[1]), name = name)
            state["local_allocations"][address] = args[1]
            return address
        if name == "localrealloc":
            previous_size = state["local_allocations"].get(args[0])
            if not args[0]:
                address = machine.allocate(size = max(1, args[1]), name = name)
                state["local_allocations"][address] = args[1]
                return address
            if previous_size == None:
                state["last_error"] = 6
                return 0
            if args[2] & 0x80:  # LMEM_MODIFY changes attributes only.
                return args[0]
            address = machine.allocate(size = max(1, args[1]), name = name)
            if previous_size and args[1]:
                machine.write(address, machine.read(args[0], min(previous_size, args[1])))
            state["local_allocations"].pop(args[0])
            machine.free(args[0])
            state["local_allocations"][address] = args[1]
            return address
        if name == "globalrealloc":
            previous = state["global_allocations"].get(args[0])
            if not args[0]:
                address = machine.allocate(size = max(1, args[1]), name = name)
                state["global_allocations"][address] = {"size": args[1], "flags": args[2], "locks": 0}
                return address
            if previous == None:
                state["last_error"] = 6
                return 0
            if args[2] & 0x80:  # GMEM_MODIFY
                previous["flags"] = args[2]
                return args[0]
            address = machine.allocate(size = max(1, args[1]), name = name)
            if previous["size"] and args[1]:
                machine.write(address, machine.read(args[0], min(previous["size"], args[1])))
            state["global_allocations"].pop(args[0])
            machine.free(args[0])
            state["global_allocations"][address] = {"size": args[1], "flags": args[2], "locks": 0}
            return address
        if name == "virtualalloc":
            requested, size, allocation_type, protect = args
            if size <= 0 or not allocation_type & 0x3000:
                state["last_error"] = 87
                return 0
            if requested:
                for base, allocation in state["virtual_allocations"].items():
                    if requested >= base and requested + size <= base + allocation["size"]:
                        allocation["protect"] = protect
                        return requested
                state["last_error"] = 487  # ERROR_INVALID_ADDRESS
                return 0
            readable = protect not in [0x01]
            writable = protect in [0x04, 0x08, 0x40, 0x80]
            executable = protect in [0x10, 0x20, 0x40, 0x80]
            address = machine.allocate(size = size, name = "VirtualAlloc", readable = readable, writable = writable, executable = executable)
            state["virtual_allocations"][address] = {"size": size, "type": allocation_type, "protect": protect}
            return address
        if name == "virtualfree":
            address, size, free_type = args
            allocation = state["virtual_allocations"].get(address)
            if free_type == 0x8000 and allocation != None and size == 0:  # MEM_RELEASE
                state["virtual_allocations"].pop(address)
                machine.free(address)
                return 1
            if free_type == 0x4000:  # MEM_DECOMMIT
                for base, candidate in state["virtual_allocations"].items():
                    if address >= base and address + size <= base + candidate["size"]:
                        return 1
            state["last_error"] = 87
            return 0
        if name == "virtualprotect":
            if not args[0] or not args[1] or not args[3]:
                state["last_error"] = 87
                return 0
            protect = args[2] & 0xff
            previous = machine.protect(
                args[0],
                args[1],
                readable = protect not in [0x01],
                writable = protect in [0x04, 0x08, 0x40, 0x80],
                executable = protect in [0x10, 0x20, 0x40, 0x80],
            )
            first = previous[0]
            if first.executable:
                old = 0x40 if first.writable else (0x20 if first.readable else 0x10)
            else:
                old = 0x04 if first.writable else (0x02 if first.readable else 0x01)
            machine.write_u32le(args[3], old)
            state["virtual_protections"][args[0]] = args[2]
            return 1
        if name == "virtualquery":
            if not args[0] or not args[1] or args[2] < 28:
                state["last_error"] = 87
                return 0
            address = args[0]
            base = address & 0xfffff000
            allocation_base = 0
            allocation_protect = 0
            region_size = 0x1000
            protect = 0
            memory_state = 0x10000  # MEM_FREE
            memory_type = 0
            found_allocation = False
            for candidate, allocation in state["virtual_allocations"].items():
                if address >= candidate and address < candidate + allocation["size"]:
                    base = candidate
                    allocation_base = candidate
                    allocation_protect = allocation["protect"]
                    region_size = allocation["size"]
                    protect = allocation["protect"]
                    memory_state = 0x1000  # MEM_COMMIT
                    memory_type = 0x20000  # MEM_PRIVATE
                    found_allocation = True
                    break
            if not found_allocation:
                following = None
                for mapping in machine.mappings:
                    if address >= mapping.start and address < mapping.start + mapping.size:
                        base = mapping.start
                        allocation_base = mapping.start
                        allocation_protect = 0x40 if mapping.executable and mapping.writable else (0x20 if mapping.executable else (0x04 if mapping.writable else 0x02))
                        region_size = mapping.size
                        protect = state["virtual_protections"].get(mapping.start, allocation_protect)
                        memory_state = 0x1000  # MEM_COMMIT
                        memory_type = 0x1000000 if mapping.name.startswith("module:") else 0x20000
                        found_allocation = True
                        break
                    if mapping.start > address and (following == None or mapping.start < following):
                        following = mapping.start
                if not found_allocation and following != None:
                    region_size = following - base
            info = binary.builder(capacity = 28)
            for value in [base, allocation_base, allocation_protect, region_size, memory_state, protect, memory_type]:
                info.u32le(value)
            machine.write(args[1], info.bytes())
            return 28
        if name in ["getmodulefilenamea", "getmodulefilenamew"]:
            return _write_string(machine, args[1], module_path, name.endswith("w"), args[2])
        if name in ["lstrlena", "lstrlenw"]:
            if name == "lstrlena":
                return len(terminated_data(machine, args[0], 1)) - 1
            return len(machine.read_cstring(args[0], encoding = "utf16le"))
        if name in ["lstrcmpa", "lstrcmpw", "lstrcmpia", "lstrcmpiw"]:
            if not name.endswith("w"):
                left = terminated_data(machine, args[0], 1)[:-1]
                right = terminated_data(machine, args[1], 1)[:-1]
                insensitive = name == "lstrcmpia"
                count = min(len(left), len(right))
                left_cursor = binary.cursor(left)
                right_cursor = binary.cursor(right)
                for unused in range(count):
                    left_byte = left_cursor.u8()
                    right_byte = right_cursor.u8()
                    if insensitive:
                        if left_byte >= 65 and left_byte <= 90:
                            left_byte += 32
                        if right_byte >= 65 and right_byte <= 90:
                            right_byte += 32
                    if left_byte != right_byte:
                        return -1 if left_byte < right_byte else 1
                return -1 if len(left) < len(right) else (1 if len(left) > len(right) else 0)
            encoding = "utf16le" if name.endswith("w") else "ascii"
            left = machine.read_cstring(args[0], encoding = encoding)
            right = machine.read_cstring(args[1], encoding = encoding)
            if name.startswith("lstrcmpi"):
                left, right = left.lower(), right.lower()
            return -1 if left < right else (1 if left > right else 0)
        if name in ["lstrcpya", "lstrcpyna"]:
            source = terminated_data(machine, args[1], 1)
            if name == "lstrcpyna":
                capacity = args[2]
                if capacity <= 0:
                    return args[0]
                source = source[:capacity]
                if len(source) == capacity:
                    output = binary.builder(capacity = capacity)
                    output.append(source[:capacity - 1])
                    output.u8(0)
                    source = output.bytes()
            machine.write(args[0], source)
            return args[0]
        if name in ["lstrcpyw", "lstrcpynw"]:
            wide = name.endswith("w")
            value = machine.read_cstring(args[1], encoding = "utf16le" if wide else "ascii")
            _write_string(machine, args[0], value, wide, args[2] if name == "lstrcpynw" else 0)
            return args[0]
        if name in ["lstrcata", "lstrcatw"]:
            wide = name.endswith("w")
            if not wide:
                left = terminated_data(machine, args[0], 1)[:-1]
                right = terminated_data(machine, args[1], 1)
                output = binary.builder(capacity = len(left) + len(right))
                output.append(left)
                output.append(right)
                machine.write(args[0], output.bytes())
                return args[0]
            encoding = "utf16le" if wide else "ascii"
            left = machine.read_cstring(args[0], encoding = encoding)
            right = machine.read_cstring(args[1], encoding = encoding)
            _write_string(machine, args[0], left + right, wide)
            return args[0]
        if name in ["interlockedincrement", "interlockeddecrement"]:
            value = machine.read_u32le(args[0])
            value = (value + (1 if name.endswith("increment") else -1)) & 0xffffffff
            builder = binary.builder(capacity = 4)
            builder.u32le(value)
            machine.write(args[0], builder.bytes())
            return value
        if name == "interlockedcompareexchange":
            previous = machine.read_u32le(args[0])
            if previous == args[2]:
                machine.write_u32le(args[0], args[1])
            return previous
        if name == "interlockedexchange":
            previous = machine.read_u32le(args[0])
            builder = binary.builder(capacity = 4)
            builder.u32le(args[1])
            machine.write(args[0], builder.bytes())
            return previous
        if name == "interlockedexchangeadd":
            previous = machine.read_u32le(args[0])
            machine.write_u32le(args[0], (previous + args[1]) & 0xffffffff)
            return previous
        return 0

    def get_process_dword(event):
        # Windows 9x's ordinal-only GetProcessDword reads fields selected by a
        # negative GPD_* offset. Registration runs as an ordinary, non-debugged
        # process with no Win16 task or inherited shell startup state.
        offset = event.args[1]
        if offset == 0:  # GPD_USERDATA
            return state["process_userdata"]
        if offset in [
            0xffffffc8,  # GPD_APP_COMPAT_FLAGS (-56)
            0xffffffcc,  # GPD_LOAD_DONE_EVENT (-52)
            0xffffffd0,  # GPD_HINSTANCE16 (-48)
            0xffffffd4,  # GPD_WINDOWS_VERSION (-44)
            0xffffffd8,  # GPD_THDB (-40)
            0xffffffdc,  # GPD_PDB (-36)
            0xffffffe0,  # GPD_STARTF_SHELLDATA (-32)
            0xffffffe4,  # GPD_STARTF_HOTKEY (-28)
            0xffffffe8,  # GPD_STARTF_SHOWWINDOW (-24)
            0xffffffec,  # GPD_STARTF_SIZE (-20)
            0xfffffff0,  # GPD_STARTF_POSITION (-16)
            0xfffffff4,  # GPD_STARTF_FLAGS (-12)
            0xfffffff8,  # GPD_PARENT (-8)
            0xfffffffc,  # GPD_FLAGS (-4)
        ]:
            return 0
        state["last_error"] = 87
        return 0

    def install(machine):
        fs = machine.segment_base("fs")
        if fs:
            machine.write_u32le(fs, 0xffffffff)
            machine.write_u32le(fs + 4, machine.stack.high)
            machine.write_u32le(fs + 8, machine.stack.low)
            machine.write_u32le(fs + 0x18, fs)
        main_name = module_name(module_path)
        for module in machine.modules:
            state["modules"][module.name] = module.base
            state["handles"][module.base] = module.name
            if module.name == main_name:
                state["main"] = module.base
        for name in virtual_modules:
            normalized = module_name(name)
            if normalized not in state["modules"]:
                state["modules"][normalized] = create_handle("module", {"name": normalized})
        # Direct imports and dynamic lookup must observe one coherent module
        # namespace. Publish semantic exports as virtual Kernel32/NTDLL images
        # while retaining import-site hooks for already-linked target modules.
        for function, argc in _KERNEL_SIGNATURES.items():
            providers = ["ntdll.dll"] if function.startswith("rtl") or function.startswith("nt") or function.startswith("zw") or function.startswith("ldr") or function.startswith("dbg") or function.startswith("etw") else ["kernel32.dll"]
            # Win9x exposes the RTL memory helpers through Kernel32, while NT
            # exports the same contract from NTDLL.
            if function in ["rtlfillmemory", "rtlmovememory", "rtlzeromemory"]:
                providers = ["kernel32.dll", "ntdll.dll"]
            for provider in providers:
                machine.provide_export(callback, module = provider, name = function, argc = argc)
        machine.provide_export(get_process_dword, module = "kernel32.dll", ordinal = 18, argc = 2)
        for imported in machine.imports:
            function = imported.name.lower()
            if _kernel_provider_module(imported.module) and function in _KERNEL_SIGNATURES:
                machine.hook(callback, address = imported.address, argc = _KERNEL_SIGNATURES[function])
            elif imported.module.lower() == "kernel32.dll" and imported.ordinal == 18:
                machine.hook(get_process_dword, address = imported.address, argc = 2)
    return emulator.plugin(install, name = "windows.kernel32", state = state)

def _version_resource(file):
    selected = None
    for resource in windows.pe(file).resources:
        if resource["type"] != "#16":
            continue
        if selected == None or resource["lang"] == "#1033":
            selected = resource["data"]
        if resource["lang"] == "#1033":
            break
    return selected

def _version_node(data, offset):
    if offset < 0 or offset + 6 > len(data):
        return None
    cursor = binary.cursor(data)
    cursor.seek(offset)
    size = cursor.u16le()
    value_length = cursor.u16le()
    value_type = cursor.u16le()
    if size < 6 or offset + size > len(data):
        return None
    key_start = offset + 6
    key_end = key_start
    while key_end + 2 <= offset + size:
        cursor.seek(key_end)
        if cursor.u16le() == 0:
            break
        key_end += 2
    if key_end + 2 > offset + size:
        return None
    key = binary.text(data[key_start:key_end], encoding = "utf16le")
    value_offset = (key_end + 2 + 3) & ~3
    value_size = value_length * 2 if value_type == 1 else value_length
    children_offset = (value_offset + value_size + 3) & ~3
    if value_offset + value_size > offset + size or children_offset > offset + size:
        return None
    return {
        "offset": offset,
        "size": size,
        "key": key,
        "value_offset": value_offset,
        "value_length": value_length,
        "value_size": value_size,
        "children_offset": children_offset,
    }

def _version_query(data, query):
    node = _version_node(data, 0)
    if node == None or node["key"] != "VS_VERSION_INFO":
        return None
    parts = [part for part in query.replace("/", "\\").split("\\") if part]
    for part in parts:
        wanted = part.lower()
        child_offset = node["children_offset"]
        child = None
        while child_offset < node["offset"] + node["size"]:
            candidate = _version_node(data, child_offset)
            if candidate == None:
                break
            if candidate["key"].lower() == wanted:
                child = candidate
                break
            child_offset = (child_offset + candidate["size"] + 3) & ~3
        if child == None:
            return None
        node = child
    return node

def version_plugin(file, module_path = "", module_files = {}):
    """Serves immutable PE version resources through the Win32 version API."""
    resources = {}
    primary_name = _module_basename(module_path)
    primary_resource = _version_resource(file)
    if primary_resource != None:
        resources[primary_name] = primary_resource
    for name, module_file in module_files.items():
        resource = _version_resource(module_file)
        if resource != None:
            resources[_module_basename(name)] = resource
    state = {"blocks": {}, "queries": []}

    def resource_for(path):
        name = _module_basename(path)
        resource = resources.get(name)
        if resource != None:
            return resource
        for module_name, module_file in module_files.items():
            if _module_basename(module_name) != name:
                continue
            resource = _version_resource(module_file)
            if resource != None:
                resources[name] = resource
            return resource
        return None

    def callback(event):
        name = event.name.lower()
        args = event.args
        machine = event.machine
        wide = name.endswith("w")
        encoding = "utf16le" if wide else "ascii"
        if name.startswith("getfileversioninfosize"):
            path = machine.read_cstring(args[0], encoding = encoding)
            resource = resource_for(path)
            state["queries"].append({"api": name, "path": path, "found": resource != None})
            if args[1]:
                machine.write_u32le(args[1], 0)
            return len(resource) if resource != None else 0
        if name.startswith("getfileversioninfo"):
            path = machine.read_cstring(args[0], encoding = encoding)
            resource = resource_for(path)
            state["queries"].append({"api": name, "path": path, "found": resource != None, "capacity": args[2]})
            if resource == None or not args[3] or args[2] < len(resource):
                return 0
            machine.write(args[3], resource)
            state["blocks"][args[3]] = resource
            return 1
        if name.startswith("verqueryvalue"):
            resource = state["blocks"].get(args[0])
            if resource == None or not args[1] or not args[2] or not args[3]:
                return 0
            query = machine.read_cstring(args[1], encoding = encoding)
            node = _version_query(resource, query)
            state["queries"].append({"api": name, "query": query, "found": node != None})
            if node == None:
                return 0
            machine.write_u32le(args[2], args[0] + node["value_offset"])
            machine.write_u32le(args[3], node["value_length"])
            return 1
        return 0

    signatures = {
        "getfileversioninfoa": 4,
        "getfileversioninfow": 4,
        "getfileversioninfosizea": 2,
        "getfileversioninfosizew": 2,
        "verqueryvaluea": 4,
        "verqueryvaluew": 4,
    }
    def install(machine):
        for function, argc in signatures.items():
            machine.provide_export(callback, module = "version.dll", name = function, argc = argc)
        for imported in machine.imports:
            name = imported.name.lower()
            if imported.module.lower() == "version.dll" and name in signatures:
                machine.hook(callback, address = imported.address, argc = signatures[name])
    return emulator.plugin(install, name = "windows.version", state = state)

def _module_basename(name):
    return name.replace("/", "\\").split("\\")[-1].lower()

def _class_server_names(module_names, server_classes, class_name, registered_server = ""):
    if registered_server:
        registered_name = _module_basename(registered_server)
        registered = [name for name in module_names if _module_basename(name) == registered_name]
        if registered:
            return registered
    owners = []
    unclassified = []
    for name in module_names:
        classes = server_classes.get(name.lower())
        if not classes:
            unclassified.append(name)
        elif class_name in classes:
            owners.append(name)
    return owners if owners else unclassified

def _invoke_target(machine, target, arguments, continuation_limit = 64, instruction_limit = 0, on_budget = None):
    """Invokes target code without converting a slice boundary into failure."""
    execution = machine.spawn(target, args = arguments)
    result = execution.run(instruction_limit = instruction_limit) if instruction_limit else execution.run()
    continuations = 0
    while result.reason == "budget" and continuations < continuation_limit:
        if on_budget != None:
            on_budget(machine)
        result = execution.run(instruction_limit = instruction_limit) if instruction_limit else execution.run()
        continuations += 1
    return result

def ole32_plugin(on_class_registration = None, on_class_activation = None, on_server_activation = None, class_server_resolver = None, server_classes = {}, class_activators = {}, target_budget_handler = None, target_instruction_limit = 100000, target_continuation_limit = 4, kernel = None):
    """Models allocation, initialization, GUIDs, and class factories.

    `on_class_registration(event, registration)` may inspect a service class
    registration and use the emulator control APIs to delimit service startup.
    """
    state = {"malloc": 0, "allocations": {}, "activations": [], "call_context": 0, "global_interfaces": {}, "global_streams": {}, "interface_streams": {}, "impersonation_depth": 0, "next_global_interface": 1, "next_global_table": 1, "next_guid": 1, "next_marshaler": 1, "next_registration": 1, "proxy_blankets": {}, "proxy_stubs": {}, "registered_classes": {}, "registrations": {}, "security": None}

    def invoke_interface(machine, interface, slot, arguments):
        vtable = machine.read_u32le(interface)
        target = machine.read_u32le(vtable + slot * 4)
        return _invoke_target(machine, target, [interface] + arguments, continuation_limit = target_continuation_limit, instruction_limit = target_instruction_limit, on_budget = target_budget_handler)

    def global_stream(machine, handle, delete_on_release):
        if handle == 0:
            handle = machine.allocate(size = 1, name = "IStream HGLOBAL")
            if kernel != None:
                kernel.state["global_allocations"][handle] = {"size": 0, "flags": 0x42, "locks": 0}
        allocation = kernel.state["global_allocations"].get(handle) if kernel != None else None
        size = allocation["size"] if allocation != None else 0
        stream = {"global": handle, "size": size, "position": 0, "references": 1, "delete": delete_on_release}

        def ensure_capacity(machine, required):
            if kernel == None:
                return False
            allocation = kernel.state["global_allocations"].get(stream["global"])
            if allocation == None:
                return False
            capacity = allocation["size"]
            if required <= capacity:
                return True
            grown = max(required, max(256, capacity * 2))
            contents = machine.read(stream["global"], stream["size"]) if stream["size"] else b""
            replacement = machine.allocate(size = grown, value = contents, name = "IStream HGLOBAL")
            kernel.state["global_allocations"].pop(stream["global"])
            machine.free(stream["global"])
            stream["global"] = replacement
            kernel.state["global_allocations"][replacement] = {
                "size": grown,
                "flags": allocation["flags"],
                "locks": allocation["locks"],
            }
            return True

        def query_interface(event):
            if not event.args[2]:
                return 0x80004003
            event.machine.write_u32le(event.args[2], event.args[0])
            stream["references"] += 1
            return 0

        def add_ref(event):
            stream["references"] += 1
            return stream["references"]

        def release(event):
            stream["references"] = max(0, stream["references"] - 1)
            if stream["references"] == 0 and stream["delete"] and kernel != None:
                allocation = kernel.state["global_allocations"].pop(stream["global"], None)
                if allocation != None:
                    event.machine.free(stream["global"])
            return stream["references"]

        def read(event):
            count = min(event.args[2], max(0, stream["size"] - stream["position"]))
            if count and not event.args[1]:
                return 0x80070057
            if count:
                event.machine.write(event.args[1], event.machine.read(stream["global"] + stream["position"], count))
            stream["position"] += count
            if event.args[3]:
                event.machine.write_u32le(event.args[3], count)
            return 0 if count == event.args[2] else 1  # S_OK / S_FALSE

        def write(event):
            if event.args[2] and not event.args[1]:
                return 0x80070057
            end = stream["position"] + event.args[2]
            if not ensure_capacity(event.machine, end):
                return 0x80030070  # STG_E_MEDIUMFULL
            if stream["position"] > stream["size"]:
                event.machine.write(stream["global"] + stream["size"], b"\x00" * (stream["position"] - stream["size"]))
            if event.args[2]:
                event.machine.write(stream["global"] + stream["position"], event.machine.read(event.args[1], event.args[2]))
            stream["position"] = end
            stream["size"] = max(stream["size"], end)
            if event.args[3]:
                event.machine.write_u32le(event.args[3], event.args[2])
            return 0

        def seek(event):
            low, high, origin, output = event.args[1], event.args[2], event.args[3], event.args[4]
            offset = low | (high << 32)
            if offset & (1 << 63):
                offset -= 1 << 64
            if origin == 0:
                position = offset
            elif origin == 1:
                position = stream["position"] + offset
            elif origin == 2:
                position = stream["size"] + offset
            else:
                return 0x80030001  # STG_E_INVALIDFUNCTION
            if position < 0 or position > 0xffffffffffffffff:
                return 0x80070057
            stream["position"] = position
            if output:
                data = binary.builder(capacity = 8)
                data.u64le(position)
                event.machine.write(output, data.bytes())
            return 0

        def set_size(event):
            size = event.args[1] | (event.args[2] << 32)
            if not ensure_capacity(event.machine, size):
                return 0x80030070
            if size > stream["size"]:
                event.machine.write(stream["global"] + stream["size"], b"\x00" * (size - stream["size"]))
            stream["size"] = size
            stream["position"] = min(stream["position"], size)
            return 0

        def stat(event):
            if not event.args[1]:
                return 0x80070057
            data = binary.builder(capacity = 72)
            data.reserve(8)
            data.u64le(stream["size"])
            data.reserve(56)
            event.machine.write(event.args[1], data.bytes())
            return 0

        def unsupported(event):
            return 0x80004001

        def success(event):
            return 0

        methods = [
            ("QueryInterface", query_interface, 3), ("AddRef", add_ref, 1), ("Release", release, 1),
            ("Read", read, 4), ("Write", write, 4), ("Seek", seek, 5), ("SetSize", set_size, 3),
            ("CopyTo", unsupported, 7), ("Commit", success, 2), ("Revert", success, 1),
            ("LockRegion", unsupported, 6), ("UnlockRegion", unsupported, 6),
            ("Stat", stat, 3), ("Clone", unsupported, 2),
        ]
        vtable = binary.builder(capacity = len(methods) * 4)
        for name, callback, argc in methods:
            vtable.u32le(machine.provide_export(callback, module = "trex.istream", name = name + str(handle), argc = argc))
        vtable_address = machine.allocate(value = vtable.bytes(), name = "IStream.vtable")
        value = binary.builder(capacity = 4)
        value.u32le(vtable_address)
        interface = machine.allocate(value = value.bytes(), name = "IStream")
        state["global_streams"][interface] = stream
        return interface

    def global_interface_table(machine, requested_iid, output):
        supported = ["{00000000-0000-0000-C000-000000000046}", "{00000146-0000-0000-C000-000000000046}"]
        if not output:
            return 0x80004003  # E_POINTER
        machine.write_u32le(output, 0)
        if _guid_text(machine, requested_iid) not in supported:
            return 0x80004002  # E_NOINTERFACE
        identifier = state["next_global_table"]
        state["next_global_table"] += 1

        def query_interface(event):
            if not event.args[2]:
                return 0x80004003
            event.machine.write_u32le(event.args[2], 0)
            if _guid_text(event.machine, event.args[1]) not in supported:
                return 0x80004002
            event.machine.write_u32le(event.args[2], event.args[0])
            return 0

        def add_ref(event):
            return 2

        def release(event):
            return 1

        def register_interface(event):
            interface, iid, cookie_output = event.args[1], event.args[2], event.args[3]
            if not interface or not iid or not cookie_output:
                return 0x80070057
            cookie = state["next_global_interface"]
            state["next_global_interface"] += 1
            retained = invoke_interface(event.machine, interface, 1, [])
            if retained.reason != "return":
                return 0x80004005
            state["global_interfaces"][cookie] = {"interface": interface, "iid": _guid_text(event.machine, iid)}
            event.machine.write_u32le(cookie_output, cookie)
            return 0

        def revoke_interface(event):
            registered = state["global_interfaces"].pop(event.args[1], None)
            if registered == None:
                return 0x800401E3  # MK_E_UNAVAILABLE
            released = invoke_interface(event.machine, registered["interface"], 2, [])
            return 0 if released.reason == "return" else 0x80004005

        def get_interface(event):
            if not event.args[2] or not event.args[3]:
                return 0x80070057
            event.machine.write_u32le(event.args[3], 0)
            registered = state["global_interfaces"].get(event.args[1])
            if registered == None:
                return 0x800401E3
            queried = invoke_interface(event.machine, registered["interface"], 0, [event.args[2], event.args[3]])
            return queried.value if queried.reason == "return" else 0x80004005

        methods = [
            ("QueryInterface", query_interface, 3), ("AddRef", add_ref, 1), ("Release", release, 1),
            ("RegisterInterfaceInGlobal", register_interface, 4),
            ("RevokeInterfaceFromGlobal", revoke_interface, 2),
            ("GetInterfaceFromGlobal", get_interface, 4),
        ]
        vtable = binary.builder(capacity = len(methods) * 4)
        for method_name, method, argc in methods:
            address = machine.provide_export(method, module = "trex.git", name = method_name + str(identifier), argc = argc)
            vtable.u32le(address)
        vtable_address = machine.allocate(value = vtable.bytes(), name = "IGlobalInterfaceTable vtable")
        value = binary.builder(capacity = 4)
        value.u32le(vtable_address)
        interface = machine.allocate(value = value.bytes(), name = "IGlobalInterfaceTable")
        machine.write_u32le(output, interface)
        return 0

    def free_threaded_marshaler(machine, outer):
        identifier = state["next_marshaler"]
        state["next_marshaler"] += 1

        def query_interface(event):
            if not event.args[2]:
                return 0x80070057
            event.machine.write_u32le(event.args[2], event.args[0])
            return 0

        def add_ref(event):
            return 2

        def release(event):
            return 1

        methods = [("QueryInterface", query_interface, 3), ("AddRef", add_ref, 1), ("Release", release, 1)]
        vtable = binary.builder(capacity = len(methods) * 4)
        for method_name, method, argc in methods:
            address = machine.provide_export(method, module = "trex.ftm", name = method_name + str(identifier), argc = argc)
            vtable.u32le(address)
        vtable_address = machine.allocate(value = vtable.bytes(), name = "free-threaded marshaler vtable")
        value = binary.builder(capacity = 8)
        value.u32le(vtable_address)
        value.u32le(outer)
        return machine.allocate(value = value.bytes(), name = "free-threaded marshaler")

    def loaded_class_object(machine, class_address, class_name, interface_address, output, activation):
        activation["attempts"] = []
        registered_server = class_server_resolver(class_name) if class_server_resolver != None else ""
        if registered_server and on_server_activation != None:
            on_server_activation(_module_basename(registered_server))
        candidates = _class_server_names(
            [module.name for module in machine.modules],
            server_classes,
            class_name,
            registered_server = registered_server,
        )
        activation["registered_server"] = registered_server
        activation["candidate_servers"] = candidates
        for module in machine.modules:
            if module.name not in candidates:
                continue
            initialized = on_server_activation(module.name) if on_server_activation != None else None
            if initialized != None and (initialized.reason != "return" or initialized.value == 0):
                activation["attempts"].append({
                    "server": module.name,
                    "reason": "module-initialization-failed",
                    "detail": initialized.detail,
                    "result": 0x80040154,
                })
                continue
            get_class_object = machine.resolve_export(module.name, name = "DllGetClassObject")
            if not get_class_object:
                continue
            machine.write(output, b"\x00\x00\x00\x00")
            factory_result = _invoke_target(machine, get_class_object, [class_address, interface_address, output], continuation_limit = target_continuation_limit, instruction_limit = target_instruction_limit, on_budget = target_budget_handler)
            activation["attempts"].append({
                "server": module.name,
                "reason": factory_result.reason,
                "detail": factory_result.detail,
                "result": factory_result.value,
            })
            if factory_result.reason != "return" or factory_result.value >= 0x80000000:
                continue
            if not machine.read_u32le(output):
                continue
            activation["server"] = module.name
            activation["factory_result"] = factory_result.value
            activation["result"] = factory_result.value
            activation["interface_pointer"] = machine.read_u32le(output)
            return factory_result.value
        return 0x80040154

    def activate_loaded_server(machine, class_address, class_name, outer, interface_address, output, activation):
        factory_iid = machine.allocate(value = guid_bytes("{00000001-0000-0000-C000-000000000046}"), name = "IID_IClassFactory")
        factory_output = machine.allocate(size = 4, name = "IClassFactory output")
        factory_result = loaded_class_object(machine, class_address, class_name, factory_iid, factory_output, activation)
        if factory_result < 0x80000000:
            factory = machine.read_u32le(factory_output)
            created = invoke_interface(machine, factory, 3, [outer, interface_address, output])
            invoke_interface(machine, factory, 2, [])
            activation["result"] = created.value if created.reason == "return" else 0x80004005
            activation["stop"] = {
                "reason": created.reason,
                "detail": created.detail,
                "eip": created.eip,
                "steps": created.steps,
                "recent": created.recent,
                "trace": created.trace,
            }
            activation["interface_pointer"] = machine.read_u32le(output)
            if created.reason == "return" and created.value < 0x80000000:
                return created.value
        return activation.get("result", factory_result)

    def activate_registered_server(machine, class_name, outer, interface_address, output, activation):
        factory = state["registered_classes"].get(class_name)
        if factory == None:
            return None
        created = invoke_interface(machine, factory, 3, [outer, interface_address, output])
        activation["server"] = "registered class object"
        activation["result"] = created.value if created.reason == "return" else 0x80004005
        activation["stop"] = {
            "reason": created.reason,
            "detail": created.detail,
            "eip": created.eip,
            "steps": created.steps,
            "recent": created.recent,
            "trace": created.trace,
        }
        activation["interface_pointer"] = machine.read_u32le(output)
        return activation["result"]

    def activate_instance(event, class_address, outer, context, interface_address, output, api):
        machine = event.machine
        class_name = _guid_text(machine, class_address)
        activation = {
            "api": api,
            "class": class_name,
            "context": context,
            "interface": _guid_text(machine, interface_address),
            "return": machine.get_register("eip"),
        }
        state["activations"].append(activation)
        machine.write_u32le(output, 0)
        if class_name == "{00000323-0000-0000-C000-000000000046}":
            result = global_interface_table(machine, interface_address, output)
            activation["server"] = "ole32.dll"
            activation["result"] = result
            activation["interface_pointer"] = machine.read_u32le(output)
            return result, activation
        registered = activate_registered_server(machine, class_name, outer, interface_address, output, activation)
        if registered != None:
            return registered, activation
        activator = class_activators.get(class_name)
        if activator != None:
            result = activator(event, activation, output)
            activation["server"] = "semantic class activator"
            activation["result"] = result
            activation["interface_pointer"] = machine.read_u32le(output)
            return result, activation
        result = activate_loaded_server(machine, class_address, class_name, outer, interface_address, output, activation)
        if result >= 0x80000000 and on_class_activation != None:
            activation["service_activation"] = on_class_activation(event, activation)
            registered = activate_registered_server(machine, class_name, outer, interface_address, output, activation)
            if registered != None:
                return registered, activation
        if "result" not in activation:
            activation["result"] = result
        return result, activation

    def callback(event):
        name = event.name.lower()
        args = event.args
        if name in ["coinitialize", "coinitializeex", "oleinitialize"]:
            return 0
        if name == "oleuninitialize":
            return None
        if name == "coinitializesecurity":
            if state["security"] != None:
                return 0x80010119  # RPC_E_TOO_LATE
            state["security"] = {
                "descriptor": args[0],
                "authentication_services": args[1],
                "authentication_service_count": args[2],
                "authentication_level": args[4],
                "impersonation_level": args[5],
                "capabilities": args[8],
            }
            return 0
        if name == "cocreateguid":
            if not args[0]:
                return 0x80070057  # E_INVALIDARG
            event.machine.write(args[0], _deterministic_guid(state["next_guid"]))
            state["next_guid"] += 1
            return 0
        if name == "cocreatefreethreadedmarshaler":
            if not args[1]:
                return 0x80070057
            event.machine.write_u32le(args[1], free_threaded_marshaler(event.machine, args[0]))
            return 0
        if name == "comarshalinterthreadinterfaceinstream":
            if not args[0] or not args[1] or not args[2]:
                return 0x80070057
            retained = invoke_interface(event.machine, args[1], 1, [])
            if retained.reason != "return":
                return 0x80004005
            stream = event.machine.allocate(size = 4, name = "inter-thread COM stream")
            state["interface_streams"][stream] = {
                "interface": args[1],
                "iid": _guid_text(event.machine, args[0]),
            }
            event.machine.write_u32le(args[2], stream)
            return 0
        if name == "cogetinterfaceandreleasestream":
            if not args[0] or not args[1] or not args[2]:
                return 0x80070057
            event.machine.write_u32le(args[2], 0)
            stream = state["interface_streams"].pop(args[0], None)
            if stream == None:
                return 0x80070057
            queried = invoke_interface(event.machine, stream["interface"], 0, [args[1], args[2]])
            invoke_interface(event.machine, stream["interface"], 2, [])
            event.machine.free(args[0])
            return queried.value if queried.reason == "return" else 0x80004005
        if name in ["clsidfromstring", "iidfromstring"]:
            if not args[1]:
                return 0x80070057  # E_INVALIDARG
            if not args[0]:
                event.machine.write(args[1], b"\x00" * 16)
                return 0
            value = event.machine.read_cstring(args[0], encoding = "utf16le")
            if len(value) == 36:
                value = "{" + value + "}"
            raw = guid_bytes(value.upper())
            if raw == None:
                return 0x800401F3  # CO_E_CLASSSTRING
            event.machine.write(args[1], raw)
            return 0
        if name == "couninitialize":
            return None
        if name == "cotaskmemfree":
            if args[0] in state["allocations"]:
                state["allocations"].pop(args[0])
                event.machine.free(args[0])
            return None
        if name == "propvariantclear":
            event.machine.write(args[0], b"\x00" * 16)
            return 0
        if name == "propvariantcopy":
            if args[0] != args[1]:
                event.machine.write(args[0], event.machine.read(args[1], 16))
            return 0
        if name == "freepropvariantarray":
            if args[1]:
                event.machine.write(args[1], b"\x00" * (args[0] * 16))
            return 0
        if name == "cotaskmemalloc":
            return _tracked_allocate(event.machine, state["allocations"], args[0], "CoTaskMemAlloc")
        if name == "createstreamonhglobal":
            if not args[2]:
                return 0x80070057
            stream = global_stream(event.machine, args[0], args[1] != 0)
            event.machine.write_u32le(args[2], stream)
            return 0
        if name == "gethglobalfromstream":
            if not args[0] or not args[1]:
                return 0x80070057
            stream = state["global_streams"].get(args[0])
            if stream == None:
                return 0x80070057
            event.machine.write_u32le(args[1], stream["global"])
            return 0
        if name == "cogetmalloc":
            event.machine.write_u32le(args[1], state["malloc"])
            return 0
        if name == "cocreateinstanceex":
            class_address, outer, context, server_info, count, results = args
            if not class_address or not count or not results:
                return 0x80070057  # E_INVALIDARG
            entries = []
            for index in range(count):
                entry = results + index * 12
                interface_address = event.machine.read_u32le(entry)
                event.machine.write_u32le(entry + 4, 0)
                event.machine.write_u32le(entry + 8, 0x80004002)  # E_NOINTERFACE
                entries.append((entry, interface_address))

            unknown = event.machine.allocate(value = guid_bytes("{00000000-0000-0000-C000-000000000046}"), name = "IID_IUnknown")
            identity_output = event.machine.allocate(size = 4, name = "CoCreateInstanceEx identity")
            created, activation = activate_instance(event, class_address, outer, context, unknown, identity_output, name)
            activation["server_info"] = server_info
            activation["interfaces"] = []
            if created >= 0x80000000:
                for entry, _ in entries:
                    event.machine.write_u32le(entry + 8, created)
                event.machine.free(identity_output)
                event.machine.free(unknown)
                return created

            identity = event.machine.read_u32le(identity_output)
            succeeded = 0
            for entry, interface_address in entries:
                result = 0x80070057  # E_INVALIDARG
                if interface_address:
                    queried = invoke_interface(event.machine, identity, 0, [interface_address, entry + 4])
                    result = queried.value if queried.reason == "return" else 0x80004005
                event.machine.write_u32le(entry + 8, result)
                activation["interfaces"].append({
                    "interface": _guid_text(event.machine, interface_address) if interface_address else "",
                    "result": result,
                    "pointer": event.machine.read_u32le(entry + 4),
                    "stop_reason": queried.reason if interface_address else "",
                    "stop_detail": queried.detail if interface_address else "",
                })
                if result < 0x80000000:
                    succeeded += 1
            invoke_interface(event.machine, identity, 2, [])
            event.machine.free(identity_output)
            event.machine.free(unknown)
            if succeeded == count:
                return 0
            if succeeded:
                return 0x00080012  # CO_S_NOTALLINTERFACES
            return 0x80004002  # E_NOINTERFACE
        if name in ["cocreateinstance", "cogetclassobject"]:
            class_name = _guid_text(event.machine, args[0])
            if name == "cocreateinstance":
                result, _ = activate_instance(event, args[0], args[1], args[2], args[3], args[4], name)
                return result
            activation = {
                "api": name,
                "class": class_name,
                "context": args[2],
                "interface": _guid_text(event.machine, args[3]),
                "return": event.machine.get_register("eip"),
            }
            state["activations"].append(activation)
            event.machine.write_u32le(args[4], 0)
            factory = state["registered_classes"].get(class_name)
            if factory != None:
                queried = invoke_interface(event.machine, factory, 0, [args[3], args[4]])
                activation["server"] = "registered class object"
                activation["result"] = queried.value if queried.reason == "return" else 0x80004005
                activation["interface_pointer"] = event.machine.read_u32le(args[4])
                return activation["result"]
            result = loaded_class_object(event.machine, args[0], class_name, args[3], args[4], activation)
            if "result" not in activation:
                activation["result"] = result
            return result
        if name == "coregisterclassobject":
            if not args[0] or not args[1] or not args[4]:
                return 0x80070057
            class_name = _guid_text(event.machine, args[0])
            cookie = state["next_registration"]
            state["next_registration"] += 1
            state["registered_classes"][class_name] = args[1]
            registration = {"class": class_name, "factory": args[1], "context": args[2], "flags": args[3]}
            state["registrations"][cookie] = registration
            event.machine.write_u32le(args[4], cookie)
            if on_class_registration != None:
                on_class_registration(event, registration)
            return 0
        if name == "coregisterpsclsid":
            if not args[0] or not args[1]:
                return 0x80070057
            state["proxy_stubs"][_guid_text(event.machine, args[0])] = _guid_text(event.machine, args[1])
            return 0
        if name == "corevokeclassobject":
            registration = state["registrations"].pop(args[0], None)
            if registration == None:
                return 0x800401E3  # MK_E_UNAVAILABLE
            if state["registered_classes"].get(registration["class"]) == registration["factory"]:
                state["registered_classes"].pop(registration["class"])
            return 0
        if name in ["coresumeclassobjects", "cosuspendclassobjects"]:
            return 0
        if name == "coimpersonateclient":
            state["impersonation_depth"] += 1
            return 0
        if name == "coreverttoself":
            if state["impersonation_depth"]:
                state["impersonation_depth"] -= 1
            return 0
        if name == "codisconnectcontext":
            return 0
        if name == "cosetproxyblanket":
            if not args[0]:
                return 0x80070057  # E_INVALIDARG
            state["proxy_blankets"][args[0]] = {
                "authentication_service": args[1],
                "authorization_service": args[2],
                "server_principal": event.machine.read_cstring(args[3], encoding = "utf16le") if args[3] and args[3] != 0xffffffff else "",
                "default_principal": args[3] == 0xffffffff,
                "authentication_level": args[4],
                "impersonation_level": args[5],
                "authentication_identity": args[6],
                "capabilities": args[7],
            }
            return 0
        if name == "coqueryproxyblanket":
            if not args[0]:
                return 0x80070057  # E_INVALIDARG
            blanket = state["proxy_blankets"].get(args[0], {
                "authentication_service": 0,
                "authorization_service": 0,
                "server_principal": "",
                "default_principal": False,
                "authentication_level": 0,
                "impersonation_level": 0,
                "authentication_identity": 0,
                "capabilities": 0,
            })
            if args[1]:
                event.machine.write_u32le(args[1], blanket["authentication_service"])
            if args[2]:
                event.machine.write_u32le(args[2], blanket["authorization_service"])
            if args[3]:
                principal = blanket["server_principal"]
                address = _tracked_allocate(event.machine, state["allocations"], (len(principal) + 1) * 2, "CoQueryProxyBlanket principal") if principal else 0
                if address:
                    event.machine.write(address, _encoded(principal, True))
                event.machine.write_u32le(args[3], address)
            if args[4]:
                event.machine.write_u32le(args[4], blanket["authentication_level"])
            if args[5]:
                event.machine.write_u32le(args[5], blanket["impersonation_level"])
            if args[6]:
                event.machine.write_u32le(args[6], blanket["authentication_identity"])
            if args[7]:
                event.machine.write_u32le(args[7], blanket["capabilities"])
            return 0
        if name == "cogetcallcontext":
            if not args[1]:
                return 0x80004003  # E_POINTER
            event.machine.write_u32le(args[1], 0)
            context = state["call_context"]
            if not context:
                return 0x80010117  # RPC_E_CALL_COMPLETE
            queried = invoke_interface(event.machine, context, 0, [args[0], args[1]])
            if queried.reason != "return":
                return 0x80004005  # E_FAIL
            return queried.value
        if name == "coswitchcallcontext":
            if not args[1]:
                return 0x80070057  # E_INVALIDARG
            event.machine.write_u32le(args[1], state["call_context"])
            state["call_context"] = args[0]
            return 0
        if name == "cogetpsclsid":
            event.machine.write(args[1], b"\x00" * 16)
            return 0x80040155  # REGDB_E_IIDNOTREG
        if name in ["cogetmarshalsizemax", "comarshalinterface", "coreleasemarshaldata", "counmarshalinterface"]:
            return 0x80004001  # E_NOTIMPL
        if name == "stringfromguid2":
            text = _guid_text(event.machine, args[0])
            _write_string(event.machine, args[1], text, True, args[2])
            return len(text) + 1
        if name in ["stringfromclsid", "stringfromiid"]:
            text = _guid_text(event.machine, args[0])
            address = event.machine.allocate(value = _encoded(text, True), name = "StringFromGUID")
            event.machine.write_u32le(args[1], address)
            return 0
        return 0

    def install(machine):
        def query_interface(event):
            event.machine.write_u32le(event.args[2], state["malloc"])
            return 0

        def add_ref(event):
            return 2

        def release(event):
            return 1

        def allocate(event):
            return _tracked_allocate(event.machine, state["allocations"], event.args[1], "IMalloc.Alloc")

        def reallocate(event):
            return _tracked_reallocate(event.machine, state["allocations"], event.args[1], event.args[2], "IMalloc.Realloc")

        def free(event):
            if event.args[1] in state["allocations"]:
                state["allocations"].pop(event.args[1])
                event.machine.free(event.args[1])
            return None

        def get_size(event):
            return state["allocations"].get(event.args[1], 0xffffffff)

        def did_alloc(event):
            return 1

        def heap_minimize(event):
            return None

        methods = [
            ("QueryInterface", query_interface, 3), ("AddRef", add_ref, 1), ("Release", release, 1),
            ("Alloc", allocate, 2), ("Realloc", reallocate, 3), ("Free", free, 2),
            ("GetSize", get_size, 2), ("DidAlloc", did_alloc, 2), ("HeapMinimize", heap_minimize, 1),
        ]
        vtable = binary.builder(capacity = len(methods) * 4)
        for name, method, argc in methods:
            address = machine.provide_export(method, module = "trex.imalloc", name = name, argc = argc)
            vtable.u32le(address)
        vtable_address = machine.allocate(value = vtable.bytes(), name = "IMalloc.vtable")
        object = binary.builder(capacity = 4)
        object.u32le(vtable_address)
        state["malloc"] = machine.allocate(value = object.bytes(), name = "IMalloc")
        for module in ["ole32.dll", "api-ms-win-core-com-l1-1-1.dll"]:
            for name, argc in _OLE_SIGNATURES.items():
                machine.provide_export(callback, module = module, name = name, argc = argc)
    return emulator.plugin(install, name = "windows.ole32", state = state)

def _resolve_type_library_path(path, libraries):
    """Returns the mapped path for a type library, including PE resources."""
    normalized = path.replace("/", "\\").lower()
    if normalized in libraries:
        return normalized
    separator = normalized.rfind("\\")
    if separator < 0:
        return None
    resource = normalized[separator + 1:]
    if not resource or any([resource[index] < "0" or resource[index] > "9" for index in range(len(resource))]):
        return None
    module = normalized[:separator]
    return module if module in libraries else None

def _registered_type_library(identifier, major, minor, lcid, registrations):
    """Resolves LoadRegTypeLib arguments against parsed type-library facts."""
    matches = []
    for item in registrations:
        library = item["library"]
        if (
            library["guid"].upper() == identifier.upper() and
            library["major"] == major and
            library["minor"] == minor
        ):
            matches.append(item)
    for item in matches:
        if item["library"]["lcid"] == lcid:
            return item
    # A neutral caller locale asks Automation to choose the installed
    # localization of the requested library.
    if lcid == 0 and matches:
        return matches[0]
    return None

def oleaut_plugin(type_libraries = {}, registered_type_libraries = []):
    """Models bounded Automation values and explicit type-library actions.

    `type_libraries` maps installed Windows paths to in-memory files. Loading a
    type library not present in that mapping fails closed.
    `registered_type_libraries` contains parsed `library` facts and their
    installed `path`, allowing LoadRegTypeLib to resolve without a host registry.
    """
    libraries = {path.replace("/", "\\").lower(): file for path, file in type_libraries.items()}
    state = {"actions": [], "arrays": {}, "error_info": 0, "next_object": 0}

    def type_info_object(machine, library, info, index):
        identifier = state["next_object"]
        state["next_object"] = identifier + 1

        def query_interface(event):
            if not event.args[2]:
                return 0x80070057
            event.machine.write_u32le(event.args[2], event.args[0])
            return 0
        def add_ref(event):
            return 2
        def release(event):
            return 1
        def interface_method(name):
            def method(event):
                state["actions"].append({
                    "kind": "type_info_method",
                    "method": name,
                    "guid": info.get("guid", ""),
                })
                args = event.args
                if name in ["GetTypeAttr", "GetTypeComp", "GetFuncDesc", "GetVarDesc", "GetRefTypeInfo", "CreateInstance", "GetContainingTypeLib"]:
                    if args[len(args) - 1]:
                        event.machine.write_u32le(args[len(args) - 1], 0)
                elif name == "GetDocumentation":
                    if args[2]:
                        event.machine.write_u32le(args[2], bstr(event.machine, info.get("name", "")))
                    for address in args[3:]:
                        if address:
                            event.machine.write_u32le(address, 0)
                elif name == "GetIDsOfNames":
                    return 0x80020006  # DISP_E_UNKNOWNNAME
                return None if name in ["ReleaseTypeAttr", "ReleaseFuncDesc", "ReleaseVarDesc"] else 0x80004001
            return method

        methods = [
            ("QueryInterface", query_interface, 3),
            ("AddRef", add_ref, 1),
            ("Release", release, 1),
            ("GetTypeAttr", interface_method("GetTypeAttr"), 2),
            ("GetTypeComp", interface_method("GetTypeComp"), 2),
            ("GetFuncDesc", interface_method("GetFuncDesc"), 3),
            ("GetVarDesc", interface_method("GetVarDesc"), 3),
            ("GetNames", interface_method("GetNames"), 5),
            ("GetRefTypeOfImplType", interface_method("GetRefTypeOfImplType"), 3),
            ("GetImplTypeFlags", interface_method("GetImplTypeFlags"), 3),
            ("GetIDsOfNames", interface_method("GetIDsOfNames"), 4),
            ("Invoke", interface_method("Invoke"), 8),
            ("GetDocumentation", interface_method("GetDocumentation"), 6),
            ("GetDllEntry", interface_method("GetDllEntry"), 6),
            ("GetRefTypeInfo", interface_method("GetRefTypeInfo"), 3),
            ("AddressOfMember", interface_method("AddressOfMember"), 4),
            ("CreateInstance", interface_method("CreateInstance"), 5),
            ("GetMops", interface_method("GetMops"), 3),
            ("GetContainingTypeLib", interface_method("GetContainingTypeLib"), 3),
            ("ReleaseTypeAttr", interface_method("ReleaseTypeAttr"), 2),
            ("ReleaseFuncDesc", interface_method("ReleaseFuncDesc"), 2),
            ("ReleaseVarDesc", interface_method("ReleaseVarDesc"), 2),
        ]
        vtable = binary.builder(capacity = len(methods) * 4)
        for name, callback, argc in methods:
            address = machine.provide_export(callback, module = "trex.typeinfo", name = name + str(identifier), argc = argc)
            vtable.u32le(address)
        vtable_address = machine.allocate(value = vtable.bytes(), name = "ITypeInfo.vtable")
        value = binary.builder(capacity = 4)
        value.u32le(vtable_address)
        return machine.allocate(value = value.bytes(), name = "ITypeInfo")

    def type_library_object(machine, registration = None):
        identifier = state["next_object"]
        state["next_object"] = identifier + 1
        library = registration["library"] if registration != None else {"types": []}
        types = library.get("types", [])

        def query_interface(event):
            if not event.args[2]:
                return 0x80070057
            event.machine.write_u32le(event.args[2], event.args[0])
            return 0
        def add_ref(event):
            return 2
        def release(event):
            return 1

        def interface_method(name):
            def method(event):
                state["actions"].append({"kind": "type_library_method", "method": name})
                args = event.args
                if name == "GetTypeInfoCount":
                    return len(types)
                if name == "GetTypeInfo":
                    if args[1] >= len(types) or not args[2]:
                        return 0x8002802B  # TYPE_E_ELEMENTNOTFOUND
                    event.machine.write_u32le(args[2], type_info_object(event.machine, library, types[args[1]], args[1]))
                    return 0
                if name == "GetTypeInfoType":
                    if args[1] >= len(types) or not args[2]:
                        return 0x8002802B
                    event.machine.write_u32le(args[2], types[args[1]]["kind"])
                    return 0
                if name == "GetTypeInfoOfGuid":
                    requested = _guid_text(event.machine, args[1])
                    for index in range(len(types)):
                        if types[index].get("guid", "").upper() == requested.upper():
                            if not args[2]:
                                return 0x80070057
                            event.machine.write_u32le(args[2], type_info_object(event.machine, library, types[index], index))
                            return 0
                    if args[2]:
                        event.machine.write_u32le(args[2], 0)
                    return 0x8002802B
                if name in ["GetLibAttr", "GetTypeComp"]:
                    if args[len(args) - 1]:
                        event.machine.write_u32le(args[len(args) - 1], 0)
                elif name == "GetDocumentation":
                    index = args[1]
                    value = library.get("name", "") if index == 0xffffffff else (types[index].get("name", "") if index < len(types) else "")
                    if args[2]:
                        event.machine.write_u32le(args[2], bstr(event.machine, value))
                    for address in args[3:]:
                        if address:
                            event.machine.write_u32le(address, 0)
                elif name == "IsName" and args[3]:
                    event.machine.write_u32le(args[3], 0)
                elif name == "FindName" and args[5]:
                    event.machine.write_u16le(args[5], 0)
                return None if name == "ReleaseTLibAttr" else 0x80004001
            return method

        methods = [
            ("QueryInterface", query_interface, 3),
            ("AddRef", add_ref, 1),
            ("Release", release, 1),
            ("GetTypeInfoCount", interface_method("GetTypeInfoCount"), 1),
            ("GetTypeInfo", interface_method("GetTypeInfo"), 3),
            ("GetTypeInfoType", interface_method("GetTypeInfoType"), 3),
            ("GetTypeInfoOfGuid", interface_method("GetTypeInfoOfGuid"), 3),
            ("GetLibAttr", interface_method("GetLibAttr"), 2),
            ("GetTypeComp", interface_method("GetTypeComp"), 2),
            ("GetDocumentation", interface_method("GetDocumentation"), 6),
            ("IsName", interface_method("IsName"), 4),
            ("FindName", interface_method("FindName"), 6),
            ("ReleaseTLibAttr", interface_method("ReleaseTLibAttr"), 2),
        ]
        vtable = binary.builder(capacity = len(methods) * 4)
        for name, callback, argc in methods:
            address = machine.provide_export(callback, module = "trex.typelib", name = name + str(identifier), argc = argc)
            vtable.u32le(address)
        vtable_address = machine.allocate(value = vtable.bytes(), name = "ITypeLib.vtable")
        value = binary.builder(capacity = 4)
        value.u32le(vtable_address)
        return machine.allocate(value = value.bytes(), name = "ITypeLib")

    def bstr(machine, value):
        encoded = binary.encode(value, encoding = "utf16le", nul = True)
        data = binary.builder(capacity = len(encoded) + 4)
        data.u32le(len(encoded) - 2)
        data.append(encoded)
        return machine.allocate(value = data.bytes(), name = "BSTR") + 4

    def byte_bstr(machine, address, size):
        data = binary.builder(capacity = size + 6)
        data.u32le(size)
        data.append(machine.read(address, size) if address else b"\x00" * size)
        data.u16le(0)
        return machine.allocate(value = data.bytes(), name = "byte BSTR") + 4

    def signed32(value):
        return value - (1 << 32) if value & 0x80000000 else value

    def array_element_size(vartype):
        if vartype in [16, 17]:
            return 1
        if vartype in [2, 11, 18]:
            return 2
        if vartype in [3, 4, 8, 9, 10, 13, 19, 22, 23]:
            return 4
        if vartype in [5, 6, 7, 20, 21]:
            return 8
        if vartype in [12, 14]:
            return 16
        return 0

    def array_features(vartype):
        return {8: 0x180, 9: 0x480, 12: 0x880, 13: 0x280}.get(vartype, 0x80)

    def create_array(machine, vartype, bounds):
        element_size = array_element_size(vartype)
        if not bounds or not element_size:
            return 0
        count = 1
        for bound in bounds:
            count *= bound[0]
            if count > 1 << 24:
                return 0
        data = machine.allocate(size = max(1, count * element_size), name = "SAFEARRAY data")
        descriptor = binary.builder(capacity = 16 + len(bounds) * 8)
        descriptor.u16le(len(bounds))
        descriptor.u16le(array_features(vartype))
        descriptor.u32le(element_size)
        descriptor.u32le(0)
        descriptor.u32le(data)
        for elements, lower in bounds:
            descriptor.u32le(elements)
            descriptor.u32le(lower & 0xffffffff)
        address = machine.allocate(value = descriptor.bytes(), name = "SAFEARRAY")
        state["arrays"][address] = {"vartype": vartype, "element_size": element_size, "bounds": list(bounds), "data": data, "locks": 0, "count": count}
        return address

    def array_index(machine, array, indices):
        meta = state["arrays"].get(array)
        if meta == None or not indices:
            return None
        cursor = binary.cursor(machine.read(indices, len(meta["bounds"]) * 4))
        offset = 0
        stride = 1
        for elements, lower in meta["bounds"]:
            index = signed32(cursor.u32le())
            if index < lower or index >= lower + elements:
                return None
            offset += (index - lower) * stride
            stride *= elements
        return meta["data"] + offset * meta["element_size"]

    def load_type_library(machine, path, output, registration):
        resolved = _resolve_type_library_path(path, libraries)
        state["actions"].append({
            "kind": "type_library",
            "path": path,
            "registration": registration,
            "found": resolved != None,
            "resolved": resolved or "",
        })
        if resolved == None or not output:
            if output:
                machine.write_u32le(output, 0)
            return 0x80029c4a  # TYPE_E_CANTLOADLIBRARY
        registered = None
        for item in registered_type_libraries:
            if item["path"].replace("/", "\\").lower() == resolved:
                registered = item
                break
        machine.write_u32le(output, type_library_object(machine, registered))
        return 0

    def callback(event, ordinal):
        args = event.args
        machine = event.machine
        if ordinal == 2:  # SysAllocString
            return bstr(machine, machine.read_cstring(args[0], encoding = "utf16le")) if args[0] else 0
        if ordinal in [3, 5]:  # SysReAllocString / SysReAllocStringLen
            if not args[0]:
                return 0
            if ordinal == 3:
                value = machine.read_cstring(args[1], encoding = "utf16le") if args[1] else ""
            else:
                value = binary.text(machine.read(args[1], args[2] * 2), encoding = "utf16le") if args[1] else "\x00" * args[2]
            machine.write_u32le(args[0], bstr(machine, value))
            return 1
        if ordinal == 4:  # SysAllocStringLen
            value = binary.text(machine.read(args[0], args[1] * 2), encoding = "utf16le") if args[0] else "\x00" * args[1]
            return bstr(machine, value)
        if ordinal == 6:  # SysFreeString
            return None
        if ordinal == 7:  # SysStringLen
            return machine.read_u32le(args[0] - 4) // 2 if args[0] else 0
        if ordinal == 8:  # VariantInit
            machine.write(args[0], b"\x00" * 16)
            return None
        if ordinal == 9:  # VariantClear
            machine.write(args[0], b"\x00" * 16)
            return 0
        if ordinal == 10:  # VariantCopy
            if args[0] != args[1]:
                machine.write(args[0], machine.read(args[1], 16))
            return 0
        if ordinal in [12, 147]:  # VariantChangeType / VariantChangeTypeEx
            if args[0] != args[1]:
                machine.write(args[0], machine.read(args[1], 16))
            return 0
        if ordinal == 15:  # SafeArrayCreate
            if args[1] == 0 or not args[2]:
                return 0
            bounds = []
            cursor = binary.cursor(machine.read(args[2], args[1] * 8))
            for unused in range(args[1]):
                bounds.append((cursor.u32le(), signed32(cursor.u32le())))
            return create_array(machine, args[0], bounds)
        if ordinal in [16, 38, 39]:  # SafeArrayDestroy / descriptor / data
            meta = state["arrays"].get(args[0])
            if meta == None:
                return 0x80070057
            if ordinal in [16, 38]:
                state["arrays"].pop(args[0])
            return 0
        if ordinal == 17:  # SafeArrayGetDim
            meta = state["arrays"].get(args[0])
            return len(meta["bounds"]) if meta != None else 0
        if ordinal == 18:  # SafeArrayGetElemsize
            meta = state["arrays"].get(args[0])
            return meta["element_size"] if meta != None else 0
        if ordinal in [19, 20]:  # SafeArrayGetUBound / SafeArrayGetLBound
            meta = state["arrays"].get(args[0])
            if meta == None or args[1] < 1 or args[1] > len(meta["bounds"]) or not args[2]:
                return 0x80070057
            elements, lower = meta["bounds"][args[1] - 1]
            machine.write_u32le(args[2], (lower + elements - 1 if ordinal == 19 else lower) & 0xffffffff)
            return 0
        if ordinal == 23:  # SafeArrayAccessData
            meta = state["arrays"].get(args[0])
            if meta == None or not args[1]:
                return 0x80070057
            meta["locks"] += 1
            machine.write_u32le(args[1], meta["data"])
            machine.write_u32le(args[0] + 8, meta["locks"])
            return 0
        if ordinal == 24:  # SafeArrayUnaccessData
            meta = state["arrays"].get(args[0])
            if meta == None or meta["locks"] == 0:
                return 0x8002000D  # DISP_E_ARRAYISLOCKED
            meta["locks"] -= 1
            machine.write_u32le(args[0] + 8, meta["locks"])
            return 0
        if ordinal in [25, 26]:  # SafeArrayGetElement / SafeArrayPutElement
            meta = state["arrays"].get(args[0])
            address = array_index(machine, args[0], args[1])
            if meta == None or address == None or not args[2]:
                return 0x8002000B  # DISP_E_BADINDEX
            if ordinal == 25:
                machine.write(args[2], machine.read(address, meta["element_size"]))
            else:
                machine.write(address, machine.read(args[2], meta["element_size"]))
            return 0
        if ordinal == 27:  # SafeArrayCopy
            meta = state["arrays"].get(args[0])
            if meta == None or not args[1]:
                return 0x80070057
            copied = create_array(machine, meta["vartype"], meta["bounds"])
            copied_meta = state["arrays"][copied]
            machine.write(copied_meta["data"], machine.read(meta["data"], meta["count"] * meta["element_size"]))
            machine.write_u32le(args[1], copied)
            return 0
        if ordinal == 40:  # SafeArrayRedim
            meta = state["arrays"].get(args[0])
            if meta == None or not args[1] or meta["locks"]:
                return 0x80070057
            bound = binary.cursor(machine.read(args[1], 8))
            replacement = list(meta["bounds"])
            replacement[0] = (bound.u32le(), signed32(bound.u32le()))
            resized = create_array(machine, meta["vartype"], replacement)
            resized_meta = state["arrays"][resized]
            copied = min(meta["count"], resized_meta["count"]) * meta["element_size"]
            machine.write(resized_meta["data"], machine.read(meta["data"], copied))
            machine.write(args[0], machine.read(resized, 16 + len(replacement) * 8))
            state["arrays"][args[0]] = resized_meta
            state["arrays"].pop(resized)
            return 0
        if ordinal == 411:  # SafeArrayCreateVector
            return create_array(machine, args[0], [(args[2], signed32(args[1]))])
        if ordinal == 77:  # SafeArrayGetVartype
            meta = state["arrays"].get(args[0])
            if meta == None or not args[1]:
                return 0x80070057
            machine.write_u16le(args[1], meta["vartype"])
            return 0
        if ordinal == 149:  # SysStringByteLen
            return machine.read_u32le(args[0] - 4) if args[0] else 0
        if ordinal == 150:  # SysAllocStringByteLen
            return byte_bstr(machine, args[0], args[1])
        if ordinal == 161:  # LoadTypeLib
            path = machine.read_cstring(args[0], encoding = "utf16le")
            return load_type_library(machine, path, args[1], 0)
        if ordinal == 162:  # LoadRegTypeLib
            identifier = _guid_text(machine, args[0])
            registration = _registered_type_library(
                identifier,
                args[1],
                args[2],
                args[3],
                registered_type_libraries,
            )
            state["actions"].append({
                "kind": "load_registered_type_library",
                "guid": identifier,
                "major": args[1],
                "minor": args[2],
                "lcid": args[3],
                "found": registration != None,
                "path": registration["path"] if registration != None else "",
            })
            if not args[4]:
                return 0x80070057  # E_INVALIDARG
            if registration == None:
                machine.write_u32le(args[4], 0)
                return 0x8002801D  # TYPE_E_LIBNOTREGISTERED
            machine.write_u32le(args[4], type_library_object(machine, registration))
            return 0
        if ordinal == 163:  # RegisterTypeLib
            state["actions"].append({"kind": "register_type_library", "object": args[0]})
            return 0
        if ordinal == 183:  # LoadTypeLibEx
            path = machine.read_cstring(args[0], encoding = "utf16le")
            return load_type_library(machine, path, args[2], args[1])
        if ordinal == 184:  # SystemTimeToVariantTime
            if not args[0] or not args[1]:
                return 0
            fields = binary.cursor(machine.read(args[0], 16))
            year = fields.u16le()
            month = fields.u16le()
            fields.u16le()  # day of week
            day = fields.u16le()
            hour = fields.u16le()
            minute = fields.u16le()
            second = fields.u16le()
            millisecond = fields.u16le()
            ticks = _filetime_ticks(year, month, day, hour, minute, second, millisecond)
            epoch = _filetime_ticks(1899, 12, 30, 0, 0, 0, 0)
            if ticks == None:
                return 0
            encoded = binary.builder(capacity = 8)
            encoded.f64le((ticks - epoch) / 864000000000.0)
            machine.write(args[1], encoded.bytes())
            return 1
        if ordinal == 186:  # UnRegisterTypeLib
            state["actions"].append({"kind": "unregister_type_library"})
            return 0
        if ordinal == 200:  # GetErrorInfo
            if not args[1]:
                return 0x80070057
            machine.write_u32le(args[1], state["error_info"])
            result = 0 if state["error_info"] else 1
            state["error_info"] = 0
            return result
        if ordinal == 201:  # SetErrorInfo
            state["error_info"] = args[1]
            return 0
        return 0

    signatures = _OLEAUT_SIGNATURES
    named_ordinals = {
        "LoadTypeLib": 161,
        "LoadRegTypeLib": 162,
        "RegisterTypeLib": 163,
        "LoadTypeLibEx": 183,
        "UnRegisterTypeLib": 186,
    }
    def binding(ordinal):
        def bound(event):
            return callback(event, ordinal)
        return bound
    def install(machine):
        for ordinal, argc in signatures.items():
            machine.provide_export(binding(ordinal), module = "oleaut32.dll", ordinal = ordinal, argc = argc)
        for name, ordinal in named_ordinals.items():
            machine.provide_export(binding(ordinal), module = "oleaut32.dll", name = name, argc = signatures[ordinal])
        for imported in machine.imports:
            if imported.module.lower() != "oleaut32.dll":
                continue
            if imported.ordinal in signatures:
                machine.hook(binding(imported.ordinal), address = imported.address, argc = signatures[imported.ordinal])
            elif imported.name in named_ordinals:
                ordinal = named_ordinals[imported.name]
                machine.hook(binding(ordinal), address = imported.address, argc = signatures[ordinal])
    return emulator.plugin(install, name = "windows.oleaut32", state = state)

def com_plugin(registry):
    """Models COM registration APIs as explicit registry writes."""
    signatures = {"coregisterpsclsid": 2}

    def callback(event):
        interface = _guid_text(event.machine, event.args[0])
        proxy = _guid_text(event.machine, event.args[1])
        registry.set_value(
            hive = "SOFTWARE",
            key = "/Classes/Interface/" + interface + "/ProxyStubClsid32",
            name = "(default)",
            type = "REG_SZ",
            value = proxy,
        )
        return 0

    def install(machine):
        for name, argc in signatures.items():
            machine.provide_export(callback, module = "ole32.dll", name = name, argc = argc)
        for imported in machine.imports:
            name = imported.name.lower()
            if imported.module.lower() == "ole32.dll" and name in signatures:
                machine.hook(callback, address = imported.address, argc = signatures[name])
    return emulator.plugin(install, name = "windows.com-registration")

def _hex(value, width):
    text = hex(value)[2:].upper()
    return "0" * (width - len(text)) + text

def _guid_text(machine, address):
    cursor = binary.cursor(machine.read(address, 16))
    return "{%s-%s-%s-%s-%s}" % (
        _hex(cursor.u32le(), 8), _hex(cursor.u16le(), 4), _hex(cursor.u16le(), 4),
        hex(cursor.bytes(2)).upper(), hex(cursor.bytes(6)).upper(),
    )

def _sddl_descriptor(value, aliases = {}):
    return sddl_security_descriptor(value, aliases = aliases)

def permissive_import_plugin(signatures, modules = []):
    """Returns zero from explicitly declared imports; undeclared calls fail closed."""
    normalized = {}
    for name, argc in signatures.items():
        normalized[name.lower()] = argc

    def callback(event):
        return 0

    def install(machine):
        for imported in machine.imports:
            if (not modules or imported.module.lower() in modules) and imported.name.lower() in normalized:
                machine.hook(callback, address = imported.address, argc = normalized[imported.name.lower()])
    return emulator.plugin(install, name = "windows.declared-stubs")

_MSVCRT_LOCALE_COUNTERS = {
    "___setlc_active_func": "setlc_active",
    "___unguarded_readlc_active_add_func": "unguarded_readlc_active",
}

_MSVCRT_LOCALE_POINTERS = {
    "___lc_handle_func": [36, "lc_handle"],
}

_MSVCRT_LOCALE_VALUES = {
    "___lc_codepage_func": 1252,
    "___lc_collate_cp_func": 1252,
}

_MSVCRT_CXX_CONSTRUCTORS = {
    # exception::exception(char const * const &). The object pointer is carried
    # in ECX by thiscall while the sole declared argument remains on the stack.
    "??0exception@@qae@abqbd@z": 1,
}

def _time_pad(value, width = 2):
    text = str(value)
    return "0" * max(0, width - len(text)) + text

def _ctype_mask(character):
    """Returns the MSVCRT character-classification bits for an ASCII codepoint."""
    digit = character >= 0x30 and character <= 0x39
    upper = character >= 0x41 and character <= 0x5a
    lower = character >= 0x61 and character <= 0x7a
    alpha = upper or lower
    space = character in [9, 10, 11, 12, 13, 32]
    control = character >= 0 and character < 0x20 or character == 0x7f
    printable = character >= 0x20 and character <= 0x7e
    graph = character >= 0x21 and character <= 0x7e
    punct = graph and not alpha and not digit
    xdigit = digit or character >= 0x41 and character <= 0x46 or character >= 0x61 and character <= 0x66
    return (
        (0x0001 if upper else 0) |
        (0x0002 if lower else 0) |
        (0x0004 if digit else 0) |
        (0x0008 if space else 0) |
        (0x0010 if punct else 0) |
        (0x0020 if control else 0) |
        (0x0040 if character in [9, 32] else 0) |
        (0x0080 if xdigit else 0) |
        (0x0100 if alpha else 0)
    )

def _strftime_text(format, tm):
    weekdays = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
    months = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]
    year = tm[5] + 1900
    hour12 = tm[2] % 12
    if hour12 == 0:
        hour12 = 12
    values = {
        "a": weekdays[tm[6] % 7][:3], "A": weekdays[tm[6] % 7],
        "b": months[tm[4] % 12][:3], "B": months[tm[4] % 12],
        "d": _time_pad(tm[3]), "e": (" " + str(tm[3]))[-2:],
        "H": _time_pad(tm[2]), "I": _time_pad(hour12),
        "j": _time_pad(tm[7] + 1, 3), "m": _time_pad(tm[4] + 1),
        "M": _time_pad(tm[1]), "p": "AM" if tm[2] < 12 else "PM",
        "S": _time_pad(tm[0]), "w": str(tm[6] % 7),
        "y": _time_pad(year % 100), "Y": str(year),
        "Z": "UTC", "z": "+0000", "%": "%",
    }
    values["U"] = _time_pad((tm[7] + 7 - tm[6]) // 7)
    monday_weekday = (tm[6] + 6) % 7
    values["W"] = _time_pad((tm[7] + 7 - monday_weekday) // 7)
    values["x"] = values["m"] + "/" + values["d"] + "/" + values["y"]
    values["X"] = values["H"] + ":" + values["M"] + ":" + values["S"]
    values["c"] = values["a"] + " " + values["b"] + " " + values["e"] + " " + values["X"] + " " + values["Y"]
    output = ""
    index = 0
    while index < len(format):
        if format[index] != "%":
            output += format[index]
            index += 1
            continue
        index += 1
        if index < len(format) and format[index] == "#":
            index += 1
        if index >= len(format):
            break
        directive = format[index]
        output += values.get(directive, "%" + directive)
        index += 1
    return output

_command_line_arguments = command_line_arguments

def _crt_main_arguments(machine, command_line, wide):
    """Allocates the argv and empty environment arrays used by CRT startup."""
    values = _command_line_arguments(command_line)
    encoding = "utf16le" if wide else "ascii"
    pointers = binary.builder(capacity = (len(values) + 1) * 4)
    for value in values:
        pointers.u32le(machine.allocate(
            value = binary.encode(value, encoding = encoding, nul = True),
            name = "msvcrt.wargv" if wide else "msvcrt.argv",
        ))
    pointers.u32le(0)
    argv = machine.allocate(
        value = pointers.bytes(),
        name = "msvcrt.wargv[]" if wide else "msvcrt.argv[]",
    )
    environment = machine.allocate(value = b"\x00\x00\x00\x00", name = "msvcrt.env[]")
    return len(values), argv, environment

def _crt_command_line_imports(machine, command_line):
    """Allocates the CRT `_acmdln` and `_wcmdln` imported data cells."""
    output = {}
    for name, encoding in [("_acmdln", "ascii"), ("_wcmdln", "utf16le")]:
        value = machine.allocate(
            value = binary.encode(command_line, encoding = encoding, nul = True),
            name = "msvcrt." + name + ".value",
        )
        pointer = binary.builder(capacity = 4)
        pointer.u32le(value)
        output[name] = pointer.bytes()
    return output

def _crt_compare_strings(machine, left, right, wide, count = None, ignore_case = False):
    """Compares CRT strings without reading past the first decisive unit."""
    if count != None and count == 0:
        return 0
    width = 2 if wide else 1
    maximum = 16384 if wide else 32768
    index = 0
    while count == None or index < count:
        if index >= maximum:
            fail("CRT string comparison exceeds %d code units" % maximum)
        left_cursor = binary.cursor(machine.read(left + index * width, width))
        right_cursor = binary.cursor(machine.read(right + index * width, width))
        left_unit = left_cursor.u16le() if wide else left_cursor.u8()
        right_unit = right_cursor.u16le() if wide else right_cursor.u8()
        if ignore_case:
            if left_unit >= 0x41 and left_unit <= 0x5a:
                left_unit += 0x20
            if right_unit >= 0x41 and right_unit <= 0x5a:
                right_unit += 0x20
        if left_unit != right_unit:
            return -1 if left_unit < right_unit else 1
        if left_unit == 0:
            return 0
        index += 1
    return 0

def _crt_compare_memory(machine, left, right, count, ignore_case = False):
    """Compares bounded guest memory in chunks and returns the first byte ordering."""
    if count > 64 << 20:
        fail("CRT memory comparison exceeds 64 MiB")
    offset = 0
    while offset < count:
        size = min(4096, count - offset)
        left_data = machine.read(left + offset, size)
        right_data = machine.read(right + offset, size)
        if left_data == right_data:
            offset += size
            continue
        index = 0
        while index < size:
            left_byte = binary.read_u8(left_data[index:index + 1])
            right_byte = binary.read_u8(right_data[index:index + 1])
            if ignore_case:
                if left_byte >= 0x41 and left_byte <= 0x5a:
                    left_byte += 0x20
                if right_byte >= 0x41 and right_byte <= 0x5a:
                    right_byte += 0x20
            if left_byte != right_byte:
                return left_byte - right_byte
            index += 1
        offset += size
    return 0

def msvcrt_plugin(kernel = None):
    """Models CRT memory, strings, locale data, and guest-backed streams."""
    state = {"strtok_next": 0, "wcstok_next": 0, "streams": {}, "descriptors": {}, "next_descriptor": 3, "allocations": {}, "actions": [], "calls": {}}
    signatures = {
        "??2@yapaxi@z": 1,
        "??3@yaxpax@z": 1,
        "malloc": 1,
        "free": 1,
        "calloc": 2,
        "realloc": 2,
        "_close": 1,
        "_access": 2,
        "_waccess": 2,
        "_lseek": 3,
        "_open": 3,
        "_read": 3,
        "_write": 3,
        "fclose": 1,
        "_filbuf": 1,
        "_flsbuf": 2,
        "feof": 1,
        "ferror": 1,
        "fflush": 1,
        "fgetc": 1,
        "fgetpos": 2,
        "fgetwc": 1,
        "fopen": 2,
        "_wfopen": 2,
        "fputc": 2,
        "fputwc": 2,
        "fread": 4,
        "fseek": 3,
        "fsetpos": 2,
        "ftell": 1,
        "fwrite": 4,
        "setvbuf": 4,
        "ungetc": 2,
        "ungetwc": 2,
        "memchr": 3,
        "memcmp": 3,
        "memcpy": 3,
        "memmove": 3,
        "memset": 3,
        "mbstowcs": 3,
        "isleadbyte": 1,
        "_ismbblead": 1,
        "_initterm": 2,
        "_initterm_e": 2,
        "__set_app_type": 1,
        "__p__fmode": 0,
        "__p__commode": 0,
        "_errno": 0,
        "__setusermatherr": 1,
        "__getmainargs": 5,
        "__wgetmainargs": 5,
        "__dllonexit": 3,
        "_onexit": 1,
        "_lock": 1,
        "_unlock": 1,
        "exit": 1,
        "_exit": 1,
        "_c_exit": 0,
        "_cexit": 0,
        "_controlfp": 2,
        "_beginthreadex": 6,
        "_xcptfilter": 2,
        "_purecall": 0,
        "setlocale": 2,
        "wcslen": 1,
        "wcstombs": 3,
        "wcscpy": 2,
        "wcscat": 2,
        "wcscmp": 2,
        "wcsncmp": 3,
        "strcmp": 2,
        "strncmp": 3,
        "strlen": 1,
        "strcpy": 2,
        "strcat": 2,
        "strncat": 3,
        "strstr": 2,
        "_strlwr": 1,
        "_mbslen": 1,
        "_mbschr": 2,
        "_mbsrchr": 2,
        "_mbsstr": 2,
        "_mbsinc": 1,
        "_mbsninc": 2,
        "_mbscmp": 2,
        "_mbsicmp": 2,
        "_mbsncmp": 3,
        "_mbsnicmp": 3,
        "_mbsnbcmp": 3,
        "_mbsnbicmp": 3,
        "_mbsnbcpy": 3,
        "_mbsnbcnt": 2,
        "_mbsnccnt": 2,
        "_ismbslead": 2,
        "wcsncpy": 3,
        "wcsstr": 2,
        "_wcsicmp": 2,
        "_wcsnicmp": 3,
        "_wcsdup": 1,
        "_wcsupr": 1,
        "_strdup": 1,
        "_stricmp": 2,
        "_strnicmp": 3,
        "_splitpath": 5,
        "_memicmp": 3,
        "strchr": 2,
        "strrchr": 2,
        "wcschr": 2,
        "wcsrchr": 2,
        "wcstok": 2,
        "strtok": 2,
        "iswspace": 1,
        "iswctype": 2,
        "isalnum": 1,
        "isalpha": 1,
        "iscntrl": 1,
        "isdigit": 1,
        "isgraph": 1,
        "islower": 1,
        "isprint": 1,
        "ispunct": 1,
        "isspace": 1,
        "isupper": 1,
        "isxdigit": 1,
        "iswalnum": 1,
        "iswalpha": 1,
        "iswcntrl": 1,
        "iswdigit": 1,
        "iswgraph": 1,
        "iswlower": 1,
        "iswprint": 1,
        "iswpunct": 1,
        "iswupper": 1,
        "iswxdigit": 1,
        "atol": 1,
        "asctime": 1,
        "_wtol": 1,
        "_wtoi": 1,
        "_wtof": 1,
        "strtoul": 3,
        "localtime": 1,
        "rand": 0,
        "printf": 16,
        "srand": 1,
        "time": 1,
        "wcstol": 3,
        "wcstoul": 3,
        "_ltoa": 3,
        "_itow": 3,
        "_ltow": 3,
        "_ui64toa": 4,
        "_ui64tow": 4,
        "tolower": 1,
        "towupper": 1,
        "towlower": 1,
        "vswprintf": 3,
        "swprintf": 16,
        "_snwprintf": 16,
        "sprintf": 16,
        "_vsnprintf": 4,
        "_vsnwprintf": 4,
        "sscanf": 16,
        "swscanf": 16,
        "swscanf_s": 16,
        "strftime": 4,
        "wcsftime": 4,
        "qsort": 4,
        "_except_handler3": 4,
        "_local_unwind2": 2,
        "?_set_new_handler@@yap6ahi@zp6ahi@z@z": 1,
        "?_set_new_mode@@yahh@z": 1,
    }
    for name in _MSVCRT_LOCALE_COUNTERS:
        signatures[name] = 0
    for name in _MSVCRT_LOCALE_POINTERS:
        signatures[name] = 0
    for name in _MSVCRT_LOCALE_VALUES:
        signatures[name] = 0
    for name, argc in _MSVCRT_CXX_CONSTRUCTORS.items():
        signatures[name] = argc

    def stream(pointer):
        return state["streams"].get(pointer)

    def open_stream(machine, path, mode):
        if kernel == None:
            return 0
        normalized = _normalize_virtual_path(path)
        paths = kernel.state["paths"]
        entry = paths.get(normalized)
        operation = mode[:1].lower()
        if operation == "r" and (entry == None or entry.get("directory", False)):
            return 0
        if operation == "w":
            entry = {"directory": False, "data": b"", "dirty": True}
            paths[normalized] = entry
        elif operation == "a" and entry == None:
            entry = {"directory": False, "data": b"", "dirty": True}
            paths[normalized] = entry
        if entry == None or entry.get("directory", False):
            return 0
        data = kernel.state["file_data"](normalized)
        base = machine.allocate(size = max(1, len(data)), value = data, name = "msvcrt.FILE buffer")
        file_data = binary.builder(capacity = 32)
        file_data.u32le(base)
        file_data.u32le(len(data))
        file_data.u32le(base)
        file_data.u32le(1 if operation == "r" else 2)
        file_data.u32le(len(state["streams"]) + 3)
        file_data.u32le(0)
        file_data.u32le(len(data))
        file_data.u32le(0)
        pointer = machine.allocate(value = file_data.bytes(), name = "msvcrt.FILE")
        state["streams"][pointer] = {
            "path": normalized,
            "offset": len(data) if operation == "a" else 0,
            "pointer": pointer,
            "base": base,
            "error": False,
            "eof": False,
            "wide_encoding": None,
        }
        set_stream_position(machine, state["streams"][pointer], state["streams"][pointer]["offset"])
        return pointer

    def sync_stream_position(machine, current):
        pointer = machine.read_u32le(current["pointer"])
        data = kernel.state["file_data"](current["path"]) if kernel != None else b""
        if pointer >= current["base"] and pointer <= current["base"] + len(data):
            current["offset"] = pointer - current["base"]

    def set_stream_position(machine, current, position):
        current["offset"] = position
        data = kernel.state["file_data"](current["path"]) if kernel != None else b""
        available = max(0, len(data) - position)
        machine.write_u32le(current["pointer"], current["base"] + min(position, len(data)))
        machine.write_u32le(current["pointer"] + 4, available)

    def stream_read(machine, pointer, size):
        current = stream(pointer)
        if current == None or kernel == None or size < 0:
            return None
        sync_stream_position(machine, current)
        data = kernel.state["file_data"](current["path"])
        start = current["offset"]
        value = data[start:start + size]
        set_stream_position(machine, current, start + len(value))
        current["eof"] = len(value) < size
        return value

    def stream_write(machine, pointer, value):
        current = stream(pointer)
        if current == None or kernel == None:
            return False
        sync_stream_position(machine, current)
        if not kernel.state["write_file_data"](current["path"], current["offset"], value, machine = machine):
            current["error"] = True
            return False
        set_stream_position(machine, current, current["offset"] + len(value))
        return True

    def callback(event):
        name = event.name.lower()
        args = event.args
        state["calls"][name] = state["calls"].get(name, 0) + 1
        if name == "__set_app_type":
            state["app_type"] = args[0]
            return None
        if name in ["__p__fmode", "__p__commode"]:
            key = name[5:]
            if key not in state:
                state[key] = event.machine.allocate(size = 4, name = "msvcrt." + key)
            return state[key]
        if name == "_errno":
            thread = kernel.state.get("current_thread") if kernel != None else None
            thread_id = thread["id"] if thread != None else 8
            errors = state.setdefault("errno", {})
            if thread_id not in errors:
                errors[thread_id] = event.machine.allocate(size = 4, name = "msvcrt.errno.%d" % thread_id)
            return errors[thread_id]
        if name == "__setusermatherr":
            state["user_math_error"] = args[0]
            return None
        if name in ["__getmainargs", "__wgetmainargs"]:
            command_line = kernel.state.get("command_line", "") if kernel != None else ""
            argc, argv, environment = _crt_main_arguments(
                event.machine,
                command_line,
                name == "__wgetmainargs",
            )
            event.machine.write_u32le(args[0], argc)
            event.machine.write_u32le(args[1], argv)
            event.machine.write_u32le(args[2], environment)
            return 0
        if name in ["exit", "_exit"]:
            event.machine.set_register("eax", args[0])
            event.machine.stop("process-exit", detail = str(args[0]))
            return None
        if name in ["_c_exit", "_cexit"]:
            return None
        if name == "_beginthreadex":
            if kernel == None:
                return 0
            return kernel.state["create_thread"](
                event,
                args[1],
                args[2],
                args[3],
                args[4],
                args[5],
            )
        if name == "_controlfp":
            previous = state.get("control_word", 0x0009001f)
            state["control_word"] = (previous & ~args[1]) | (args[0] & args[1])
            return previous
        if name in ["_xcptfilter", "_purecall"]:
            return 0
        if name == "setlocale":
            if args[1]:
                state["locale"] = event.machine.read_cstring(args[1], encoding = "ascii")
            value = state.get("locale", "C")
            return event.machine.allocate(value = binary.encode(value, encoding = "ascii", nul = True), name = "msvcrt.locale")
        if name in ["free", "??3@yaxpax@z"]:
            if args[0] in state["allocations"]:
                state["allocations"].pop(args[0])
                event.machine.free(args[0])
            return None
        if name in ["fopen", "_wfopen"]:
            wide = name == "_wfopen"
            encoding = "utf16le" if wide else "ascii"
            path = event.machine.read_cstring(args[0], encoding = encoding)
            mode = event.machine.read_cstring(args[1], encoding = encoding)
            result = open_stream(event.machine, path, mode)
            if len(state["actions"]) < 256:
                state["actions"].append({"api": name, "path": path, "mode": mode, "result": result})
            return result
        if name == "_open":
            path = event.machine.read_cstring(args[0], encoding = "ascii")
            flags = args[1]
            if flags & 0x0100:
                mode = "a" if flags & 0x0008 else "w"
            else:
                mode = "r"
            pointer = open_stream(event.machine, path, mode)
            if pointer == 0:
                return 0xffffffff
            descriptor = state["next_descriptor"]
            state["next_descriptor"] = descriptor + 1
            state["descriptors"][descriptor] = pointer
            if len(state["actions"]) < 256:
                state["actions"].append({"api": name, "path": path, "flags": flags, "descriptor": descriptor})
            return descriptor
        if name == "_close":
            pointer = state["descriptors"].pop(args[0], None)
            if pointer == None:
                return 0xffffffff
            state["streams"].pop(pointer, None)
            return 0
        if name in ["_access", "_waccess"]:
            wide = name == "_waccess"
            path = event.machine.read_cstring(args[0], encoding = "utf16le" if wide else "ascii")
            allowed = kernel != None and _virtual_path_access(kernel.state["paths"], path, args[1])
            if len(state["actions"]) < 256:
                state["actions"].append({"api": name, "path": path, "mode": args[1], "allowed": allowed})
            return 0 if allowed else 0xffffffff
        if name == "_splitpath":
            path = event.machine.read_cstring(args[0], encoding = "ascii").replace("/", "\\")
            drive = path[:2] if len(path) >= 2 and path[1:2] == ":" else ""
            remainder = path[len(drive):]
            parts = remainder.split("\\")
            leaf = parts[-1]
            directory = remainder[:-len(leaf)] if leaf else remainder
            dot = leaf.rfind(".")
            filename = leaf[:dot] if dot > 0 else leaf
            extension = leaf[dot:] if dot > 0 else ""
            for address, value in [
                (args[1], drive),
                (args[2], directory),
                (args[3], filename),
                (args[4], extension),
            ]:
                if address:
                    event.machine.write(address, binary.encode(value, encoding = "ascii", nul = True))
            return None
        if name in ["_read", "_write"]:
            pointer = state["descriptors"].get(args[0])
            if pointer == None:
                return 0xffffffff
            if name == "_read":
                value = stream_read(event.machine, pointer, args[2])
                if value == None:
                    return 0xffffffff
                event.machine.write(args[1], value)
                return len(value)
            value = event.machine.read(args[1], args[2])
            return len(value) if stream_write(event.machine, pointer, value) else 0xffffffff
        if name == "_lseek":
            pointer = state["descriptors"].get(args[0])
            current = stream(pointer) if pointer != None else None
            if current == None or kernel == None:
                return 0xffffffff
            offset = args[1] - (1 << 32) if args[1] & 0x80000000 else args[1]
            if args[2] == 0:
                position = offset
            elif args[2] == 1:
                position = current["offset"] + offset
            elif args[2] == 2:
                position = len(kernel.state["file_data"](current["path"])) + offset
            else:
                return 0xffffffff
            if position < 0:
                return 0xffffffff
            set_stream_position(event.machine, current, position)
            return position
        if name == "fclose":
            return 0 if state["streams"].pop(args[0], None) != None else 0xffffffff
        if name == "_filbuf":
            value = stream_read(event.machine, args[0], 1)
            return binary.read_u8(value) if value != None and len(value) == 1 else 0xffffffff
        if name == "_flsbuf":
            output = binary.builder(capacity = 1)
            output.u8(args[0] & 0xff)
            return args[0] if stream_write(event.machine, args[1], output.bytes()) else 0xffffffff
        if name in ["fflush", "setvbuf"]:
            return 0 if stream(args[0]) != None else 0xffffffff
        if name in ["feof", "ferror"]:
            current = stream(args[0])
            if current == None:
                return 0
            return 1 if current["eof" if name == "feof" else "error"] else 0
        if name in ["fgetc", "fgetwc"]:
            current = stream(args[0])
            if current == None:
                return 0xffffffff
            if name == "fgetwc" and current["wide_encoding"] == None:
                data = kernel.state["file_data"](current["path"]) if kernel != None else b""
                if current["offset"] == 0 and len(data) >= 2 and data[:2] == b"\xff\xfe":
                    current["wide_encoding"] = "utf16le"
                    current["offset"] = 2
                else:
                    current["wide_encoding"] = "ascii"
            width = 2 if name == "fgetwc" and current["wide_encoding"] == "utf16le" else 1
            value = stream_read(event.machine, args[0], width)
            if value == None or len(value) != width:
                return 0xffffffff
            cursor = binary.cursor(value)
            result = cursor.u16le() if width == 2 else cursor.u8()
            if len(state["actions"]) < 256:
                state["actions"].append({"api": name, "stream": args[0], "value": result, "width": width})
            return result
        if name in ["fputc", "fputwc"]:
            output = binary.builder(capacity = 2)
            current = stream(args[1])
            if name == "fputwc" and current != None and current["wide_encoding"] == "utf16le":
                output.u16le(args[0] & 0xffff)
            else:
                output.u8(args[0] & 0xff)
            return args[0] if stream_write(event.machine, args[1], output.bytes()) else 0xffffffff
        if name in ["ungetc", "ungetwc"]:
            current = stream(args[1])
            width = 2 if name == "ungetwc" and current != None and current["wide_encoding"] == "utf16le" else 1
            if current == None:
                return 0xffffffff
            sync_stream_position(event.machine, current)
            if current["offset"] < width:
                return 0xffffffff
            set_stream_position(event.machine, current, current["offset"] - width)
            current["eof"] = False
            return args[0]
        if name == "fread":
            total = args[1] * args[2]
            value = stream_read(event.machine, args[3], total)
            if value == None or args[1] == 0:
                return 0
            event.machine.write(args[0], value)
            result = len(value) // args[1]
            if len(state["actions"]) < 256:
                return_address = event.machine.get_register("eip")
                state["actions"].append({"api": name, "stream": args[3], "size": args[1], "count": args[2], "bytes": len(value), "result": result, "preview": hex(value[:32]), "return": return_address})
            return result
        if name == "fwrite":
            total = args[1] * args[2]
            if args[1] == 0:
                return 0
            value = event.machine.read(args[0], total)
            result = args[2] if stream_write(event.machine, args[3], value) else 0
            if len(state["actions"]) < 256:
                state["actions"].append({"api": name, "stream": args[3], "size": args[1], "count": args[2], "result": result, "preview": hex(value[:32])})
            return result
        if name == "fseek":
            current = stream(args[0])
            if current == None or kernel == None:
                return 0xffffffff
            sync_stream_position(event.machine, current)
            offset = args[1] - (1 << 32) if args[1] & 0x80000000 else args[1]
            if args[2] == 0:
                position = offset
            elif args[2] == 1:
                position = current["offset"] + offset
            elif args[2] == 2:
                position = len(kernel.state["file_data"](current["path"])) + offset
            else:
                return 0xffffffff
            if position < 0:
                return 0xffffffff
            set_stream_position(event.machine, current, position)
            current["eof"] = False
            if len(state["actions"]) < 256:
                state["actions"].append({"api": name, "stream": args[0], "offset": offset, "origin": args[2], "position": position})
            return 0
        if name == "ftell":
            current = stream(args[0])
            if current != None:
                sync_stream_position(event.machine, current)
            return current["offset"] if current != None else 0xffffffff
        if name == "fgetpos":
            current = stream(args[0])
            if current == None or not args[1]:
                return 0xffffffff
            sync_stream_position(event.machine, current)
            event.machine.write_u32le(args[1], current["offset"])
            return 0
        if name == "fsetpos":
            current = stream(args[0])
            if current == None or not args[1]:
                return 0xffffffff
            set_stream_position(event.machine, current, event.machine.read_u32le(args[1]))
            current["eof"] = False
            return 0
        if name == "time":
            if args[0]:
                event.machine.write_u32le(args[0], 0)
            return 0
        if name == "localtime":
            # 1970-01-01 00:00:00 UTC in the nine-field 32-bit tm layout.
            values = [0, 0, 0, 1, 0, 70, 4, 0, 0]
            output = binary.builder(capacity = len(values) * 4)
            for value in values:
                output.u32le(value)
            return event.machine.allocate(value = output.bytes(), name = "msvcrt.tm")
        if name == "asctime":
            return event.machine.allocate(value = binary.encode("Thu Jan  1 00:00:00 1970\n", encoding = "ascii", nul = True), name = "msvcrt.asctime")
        if name in ["strftime", "wcsftime"]:
            wide = name == "wcsftime"
            format = event.machine.read_cstring(args[2], encoding = "utf16le" if wide else "ascii")
            cursor = binary.cursor(event.machine.read(args[3], 36))
            tm = []
            for unused in range(9):
                value = cursor.u32le()
                tm.append(value - (1 << 32) if value & 0x80000000 else value)
            value = _strftime_text(format, tm)
            if not args[0] or args[1] == 0 or len(value) + 1 > args[1]:
                return 0
            _write_string(event.machine, args[0], value, wide, args[1])
            return len(value)
        if name == "srand":
            state["random"] = args[0]
            return None
        if name == "rand":
            state["random"] = (state.get("random", 1) * 214013 + 2531011) & 0xffffffff
            return (state["random"] >> 16) & 0x7fff
        if name in ["?_set_new_handler@@yap6ahi@zp6ahi@z@z", "?_set_new_mode@@yahh@z"]:
            return 0
        if name in _MSVCRT_CXX_CONSTRUCTORS:
            return event.machine.get_register("ecx")
        if name in ["isleadbyte", "_ismbblead"]:
            return 0
        if name in _MSVCRT_LOCALE_COUNTERS:
            return state[_MSVCRT_LOCALE_COUNTERS[name]]
        if name in _MSVCRT_LOCALE_POINTERS:
            return state[_MSVCRT_LOCALE_POINTERS[name][1]]
        if name in _MSVCRT_LOCALE_VALUES:
            return _MSVCRT_LOCALE_VALUES[name]
        if name in ["_initterm", "_initterm_e"]:
            address = args[0]
            while address < args[1]:
                target = event.machine.read_u32le(address)
                address += 4
                if target == 0:
                    continue
                # CRT constructors execute inside the startup routine's SEH
                # scope; protected runtimes use that outer frame deliberately.
                result = event.machine.invoke(target, inherit_exceptions = True)
                state["actions"].append({
                    "api": name,
                    "initializer": target,
                    "reason": result.reason,
                    "detail": result.detail,
                    "eip": result.eip,
                    "steps": result.steps,
                    "recent": result.recent,
                })
                if result.reason != "return":
                    fail("CRT initializer at %s stopped with %s at %s: %s" % (hex(target), result.reason, hex(result.eip), result.detail))
                if name == "_initterm_e" and result.value != 0:
                    return result.value
            return 0
        if name in ["__dllonexit", "_onexit"]:
            return args[0]
        if name in ["_lock", "_unlock"]:
            return None
        if name in ["malloc", "??2@yapaxi@z"]:
            return _tracked_allocate(event.machine, state["allocations"], args[0], "msvcrt.alloc")
        if name == "calloc":
            return _tracked_allocate(event.machine, state["allocations"], args[0] * args[1], "msvcrt.calloc")
        if name == "realloc":
            return _tracked_reallocate(event.machine, state["allocations"], args[0], args[1], "msvcrt.realloc")
        if name in ["memcpy", "memmove"]:
            if args[2]:
                event.machine.write(args[0], event.machine.read(args[1], args[2]))
            return args[0]
        if name == "memset":
            if not args[2]:
                return args[0]
            byte = args[1] & 0xff
            block = binary.builder(capacity = args[2])
            block.reserve(args[2], fill = byte)
            event.machine.write(args[0], block.bytes())
            return args[0]
        if name == "memcmp":
            return _crt_compare_memory(event.machine, args[0], args[1], args[2])
        if name == "memchr":
            remaining = args[2]
            offset = 0
            wanted = args[1] & 0xff
            needle = bytes([wanted])
            while remaining:
                length = min(remaining, 4096)
                data = event.machine.read(args[0] + offset, length)
                for index in range(len(data)):
                    if data[index] == needle:
                        return args[0] + offset + index
                offset += length
                remaining -= length
            return 0
        if name == "mbstowcs":
            value = event.machine.read_cstring(args[1], encoding = "ascii")
            if not args[0]:
                return len(value)
            encoded = binary.encode(value[:args[2]], encoding = "utf16le")
            event.machine.write(args[0], encoded)
            if len(value) < args[2]:
                event.machine.write(args[0] + len(value) * 2, b"\x00\x00")
            return min(len(value), args[2])
        if name == "wcstombs":
            value = event.machine.read_cstring(args[1], encoding = "utf16le")
            if not args[0]:
                return len(value)
            encoded = binary.encode(value[:args[2]], encoding = "ascii")
            event.machine.write(args[0], encoded)
            if len(value) < args[2]:
                event.machine.write(args[0] + len(value), b"\x00")
            return min(len(value), args[2])
        if name == "wcslen":
            return len(event.machine.read_cstring(args[0], encoding = "utf16le"))
        if name in ["strlen", "_mbslen"]:
            return len(event.machine.read_cstring(args[0], encoding = "ascii"))
        if name in ["strcpy", "strcat", "strncat", "_mbsnbcpy"]:
            value = event.machine.read_cstring(args[1], encoding = "ascii")
            if name in ["strncat", "_mbsnbcpy"]:
                value = value[:args[2]]
            if name in ["strcat", "strncat"]:
                value = event.machine.read_cstring(args[0], encoding = "ascii") + value
            encoded = binary.encode(value, encoding = "ascii", nul = name != "_mbsnbcpy" or len(value) < args[2])
            if name == "_mbsnbcpy":
                encoded = encoded[:args[2]]
                if len(encoded) < args[2]:
                    padding = binary.builder(capacity = args[2] - len(encoded))
                    padding.reserve(args[2] - len(encoded))
                    encoded += padding.bytes()
            event.machine.write(args[0], encoded)
            return args[0]
        if name == "_strlwr":
            value = event.machine.read_cstring(args[0], encoding = "ascii").lower()
            event.machine.write(args[0], binary.encode(value, encoding = "ascii", nul = True))
            return args[0]
        if name in ["_mbsinc", "_mbsninc"]:
            count = 1 if name == "_mbsinc" else args[1]
            value = event.machine.read_cstring(args[0], encoding = "ascii")
            return args[0] + min(count, len(value))
        if name in ["_mbsnbcnt", "_mbsnccnt"]:
            value = event.machine.read_cstring(args[0], encoding = "ascii")
            return min(len(value), args[1])
        if name == "_ismbslead":
            # The modeled C locale is single-byte ASCII, so there are no lead bytes.
            return 0
        if name in ["_wcsdup", "_strdup"]:
            wide = name == "_wcsdup"
            value = event.machine.read_cstring(args[0], encoding = "utf16le" if wide else "ascii")
            return event.machine.allocate(value = binary.encode(value, encoding = "utf16le" if wide else "ascii", nul = True), name = "msvcrt." + name)
        if name in ["wcscpy", "wcscat"]:
            value = event.machine.read_cstring(args[1], encoding = "utf16le")
            if name == "wcscat":
                value = event.machine.read_cstring(args[0], encoding = "utf16le") + value
            _write_string(event.machine, args[0], value, True)
            return args[0]
        if name == "wcsncpy":
            value = event.machine.read_cstring(args[1], encoding = "utf16le")[:args[2]]
            encoded = binary.encode(value, encoding = "utf16le")
            output = binary.builder(capacity = args[2] * 2)
            output.append(encoded)
            output.reserve(args[2] * 2 - len(encoded))
            event.machine.write(args[0], output.bytes())
            return args[0]
        if name in ["wcscmp", "wcsncmp", "strcmp", "strncmp", "_wcsicmp", "_wcsnicmp", "_stricmp", "_strnicmp", "_mbscmp", "_mbsicmp", "_mbsncmp", "_mbsnicmp", "_mbsnbcmp", "_mbsnbicmp"]:
            wide = "wcs" in name
            bounded = name in ["wcsncmp", "strncmp", "_wcsnicmp", "_strnicmp", "_mbsncmp", "_mbsnicmp", "_mbsnbcmp", "_mbsnbicmp"]
            return _crt_compare_strings(
                event.machine,
                args[0],
                args[1],
                wide,
                count = args[2] if bounded else None,
                ignore_case = name in ["_wcsicmp", "_wcsnicmp", "_stricmp", "_strnicmp", "_mbsicmp", "_mbsnicmp", "_mbsnbicmp"],
            )
        if name == "wcsstr":
            value = event.machine.read_cstring(args[0], encoding = "utf16le")
            needle = event.machine.read_cstring(args[1], encoding = "utf16le")
            index = value.find(needle)
            return 0 if index < 0 else args[0] + index * 2
        if name == "_wcsupr":
            value = event.machine.read_cstring(args[0], encoding = "utf16le").upper()
            _write_string(event.machine, args[0], value, True)
            return args[0]
        if name == "_memicmp":
            return _crt_compare_memory(event.machine, args[0], args[1], args[2], ignore_case = True)
        if name in ["strchr", "strrchr", "wcschr", "wcsrchr", "_mbschr", "_mbsrchr"]:
            wide = name.startswith("wcs")
            width = 2 if wide else 1
            value = event.machine.read_cstring(args[0], encoding = "utf16le" if wide else "ascii")
            codepoint = args[1] & (0xffff if wide else 0xff)
            if codepoint == 0:
                return args[0] + len(value) * width
            character_data = binary.builder(capacity = width)
            if wide:
                character_data.u16le(codepoint)
            else:
                character_data.u8(codepoint)
            character = binary.text(character_data.bytes(), encoding = "utf16le" if wide else "ascii")
            index = value.rfind(character) if name in ["strrchr", "wcsrchr", "_mbsrchr"] else value.find(character)
            return 0 if index < 0 else args[0] + index * width
        if name in ["strstr", "_mbsstr"]:
            value = event.machine.read_cstring(args[0], encoding = "ascii")
            needle = event.machine.read_cstring(args[1], encoding = "ascii")
            index = value.find(needle)
            return 0 if index < 0 else args[0] + index
        if name in ["wcstok", "strtok"]:
            wide = name == "wcstok"
            width = 2 if wide else 1
            encoding = "utf16le" if wide else "ascii"
            state_name = "wcstok_next" if wide else "strtok_next"
            current = args[0] if args[0] else state.get(state_name, 0)
            if not current:
                return 0
            delimiters = event.machine.read_cstring(args[1], encoding = encoding)
            value = event.machine.read_cstring(current, encoding = encoding)
            start = 0
            while start < len(value) and value[start] in delimiters:
                start += 1
            if start == len(value):
                state[state_name] = 0
                return 0
            end = start
            while end < len(value) and value[end] not in delimiters:
                end += 1
            token = current + start * width
            if end < len(value):
                event.machine.write(current + end * width, b"\x00\x00" if wide else b"\x00")
                state[state_name] = current + (end + 1) * width
            else:
                state[state_name] = 0
            return token
        if name == "iswspace":
            return 1 if args[0] in [9, 10, 11, 12, 13, 32] else 0
        if name == "iswctype":
            return _ctype_mask(args[0]) & args[1]
        if name in ["isalnum", "isalpha", "iscntrl", "isdigit", "isgraph", "islower", "isprint", "ispunct", "isspace", "isupper", "isxdigit", "iswalnum", "iswalpha", "iswcntrl", "iswdigit", "iswgraph", "iswlower", "iswprint", "iswpunct", "iswupper", "iswxdigit"]:
            character = args[0]
            digit = character >= 0x30 and character <= 0x39
            upper = character >= 0x41 and character <= 0x5a
            lower = character >= 0x61 and character <= 0x7a
            alpha = upper or lower
            space = character in [9, 10, 11, 12, 13, 32]
            control = character >= 0 and character < 0x20 or character == 0x7f
            printable = character >= 0x20 and character <= 0x7e
            graph = character >= 0x21 and character <= 0x7e
            punct = graph and not alpha and not digit
            xdigit = digit or character >= 0x41 and character <= 0x46 or character >= 0x61 and character <= 0x66
            kind = name[3:] if name.startswith("isw") else name[2:]
            matched = {
                "alnum": alpha or digit, "alpha": alpha, "cntrl": control,
                "digit": digit, "graph": graph, "lower": lower,
                "print": printable, "punct": punct, "space": space,
                "upper": upper, "xdigit": xdigit,
            }[kind]
            return 1 if matched else 0
        if name in ["atol", "_wtol", "_wtoi", "strtoul", "wcstol", "wcstoul"]:
            wide = name in ["_wtol", "_wtoi", "wcstol", "wcstoul"]
            value = event.machine.read_cstring(args[0], encoding = "utf16le" if wide else "ascii")
            base = args[2] if name in ["strtoul", "wcstol", "wcstoul"] else 10
            parsed = _parse_c_integer(value, base)
            if name in ["strtoul", "wcstol", "wcstoul"] and args[1]:
                event.machine.write_u32le(args[1], args[0] + parsed["consumed"] * (2 if wide else 1))
            return parsed["value"]
        if name == "_wtof":
            value = event.machine.read_cstring(args[0], encoding = "utf16le")
            parsed = _scan_float(value, "%lf")
            return 0.0 if parsed == None else parsed["value"]
        if name in ["_ltoa", "_itow", "_ltow"]:
            value = args[0] - (1 << 32) if args[0] & 0x80000000 else args[0]
            radix = args[2]
            text = str(value) if value < 0 and radix == 10 else _radix_text(value & 0xffffffff, radix)
            _write_string(event.machine, args[1], text, name in ["_itow", "_ltow"])
            return args[1]
        if name in ["_ui64toa", "_ui64tow"]:
            value = args[0] | (args[1] << 32)
            _write_string(event.machine, args[2], _radix_text(value, args[3]), name == "_ui64tow")
            return args[2]
        if name == "towupper":
            return args[0] - 32 if args[0] >= 0x61 and args[0] <= 0x7a else args[0]
        if name in ["tolower", "towlower"]:
            return args[0] + 32 if args[0] >= 0x41 and args[0] <= 0x5a else args[0]
        if name in ["swprintf", "_snwprintf"]:
            format_index = 1 if name == "swprintf" else 2
            values_index = 2 if name == "swprintf" else 3
            format = event.machine.read_cstring(args[format_index], encoding = "utf16le")
            value = _format_win32(event.machine, format, args[values_index:], True)
            if name == "swprintf":
                _write_string(event.machine, args[0], value, True)
                return len(value)
            written = value[:args[1]]
            event.machine.write(args[0], binary.encode(written, encoding = "utf16le"))
            if len(value) < args[1]:
                event.machine.write(args[0] + len(written) * 2, b"\x00\x00")
            return len(value) if len(value) <= args[1] else 0xffffffff
        if name in ["printf", "sprintf"]:
            format_index = 0 if name == "printf" else 1
            format = event.machine.read_cstring(args[format_index], encoding = "ascii")
            value = _format_win32(event.machine, format, args[format_index + 1:], False)
            if name == "sprintf":
                _write_string(event.machine, args[0], value, False)
            return len(value)
        if name == "_vsnprintf":
            if len(state["actions"]) < 256:
                state["actions"].append({"api": name, "args": list(args), "return": event.return_address})
            format = event.machine.read_cstring(args[2], encoding = "ascii")
            values = [event.machine.read_u32le(args[3] + index * 4) for index in range(16)]
            value = _format_win32(event.machine, format, values, False)
            written = value[:args[1]]
            if args[1]:
                event.machine.write(args[0], binary.encode(written, encoding = "ascii"))
                if len(value) < args[1]:
                    event.machine.write(args[0] + len(written), b"\x00")
            return len(value) if len(value) <= args[1] else 0xffffffff
        if name in ["vswprintf", "_vsnwprintf"]:
            if len(state["actions"]) < 256:
                state["actions"].append({"api": name, "args": list(args), "return": event.return_address})
            format_index = 1 if name == "vswprintf" else 2
            values_index = 2 if name == "vswprintf" else 3
            format = event.machine.read_cstring(args[format_index], encoding = "utf16le")
            values = [event.machine.read_u32le(args[values_index] + index * 4) for index in range(16)]
            value = _format_win32(event.machine, format, values, True)
            if name == "_vsnwprintf":
                written = value[:args[1]]
                event.machine.write(args[0], binary.encode(written, encoding = "utf16le"))
                if len(value) < args[1]:
                    event.machine.write(args[0] + len(written) * 2, b"\x00\x00")
                return len(value) if len(value) <= args[1] else 0xffffffff
            _write_string(event.machine, args[0], value, True)
            return len(value)
        if name in ["sscanf", "swscanf", "swscanf_s"]:
            encoding = "utf16le" if name != "sscanf" else "ascii"
            source = event.machine.read_cstring(args[0], encoding = encoding).strip()
            format = event.machine.read_cstring(args[1], encoding = encoding).strip()
            if len(state["actions"]) < 256:
                state["actions"].append({"api": name, "source": source[:256], "format": format[:256]})
            parsed = _scan_integer(source, format)
            if parsed == None:
                parsed = _scan_float(source, format)
            if parsed == None or not args[2]:
                return 0
            if parsed.get("floating", False):
                if parsed["bits"] == 64:
                    event.machine.write_f64le(args[2], parsed["value"])
                else:
                    event.machine.write_f32le(args[2], parsed["value"])
            elif parsed["bits"] == 16:
                event.machine.write_u16le(args[2], parsed["value"])
            elif parsed["bits"] == 64:
                event.machine.write_u64le(args[2], parsed["value"])
            else:
                event.machine.write_u32le(args[2], parsed["value"])
            return 1
        if name == "_local_unwind2":
            # The emulated process owns no host resources and is discarded as
            # one unit. Target cleanup routines still run when called directly;
            # compiler-maintained local unwind tables need no host-side action.
            return None
        if name in ["qsort", "_except_handler3"]:
            return 0
        return 0

    def install(machine):
        for name, state_name in _MSVCRT_LOCALE_COUNTERS.items():
            state[state_name] = machine.allocate(size = 4, name = "msvcrt." + name)
        for name, spec in _MSVCRT_LOCALE_POINTERS.items():
            state[spec[1]] = machine.allocate(size = spec[0], name = "msvcrt." + name)
        imported_data = {
            "_adjust_fdiv": b"\x00\x00\x00\x00",
        }
        if kernel != None:
            imported_data.update(_crt_command_line_imports(
                machine,
                kernel.state.get("command_line", ""),
            ))
        for name, value in imported_data.items():
            machine.provide_export(
                module = "msvcrt.dll",
                name = name,
                value = value,
            )
        for name, argc in signatures.items():
            convention = "stdcall" if name in _MSVCRT_CXX_CONSTRUCTORS else "cdecl"
            for module in ["msvcrt.dll", "crtdll.dll"]:
                machine.provide_export(
                    callback,
                    module = module,
                    name = name,
                    argc = argc,
                    convention = convention,
                )
        for imported in machine.imports:
            name = imported.name.lower()
            module = imported.module.lower()
            if module not in ["msvcrt.dll", "crtdll.dll", "ntdll.dll"]:
                continue
            if name in signatures:
                # Modeled thiscall methods carry `this` in ECX and clean their
                # declared stack arguments, matching the target's `ret N`.
                convention = "stdcall" if name in _MSVCRT_CXX_CONSTRUCTORS else "cdecl"
                machine.hook(callback, address = imported.address, argc = signatures[name], convention = convention)
    def read_stream_bytes(machine, pointer, size):
        return stream_read(machine, pointer, size)

    return emulator.plugin(
        install,
        name = "windows.msvcrt",
        state = state,
        attrs = {"read_stream": read_stream_bytes},
    )

_MAKE_ABSOLUTE_SD_ARGUMENTS = 11

_WELL_KNOWN_SIDS = {
    0: [0, [0]],
    1: [1, [0]],
    2: [2, [0]],
    3: [3, [0]],
    4: [3, [1]],
    5: [3, [2]],
    6: [3, [3]],
    7: [5, []],
    8: [5, [1]],
    9: [5, [2]],
    10: [5, [3]],
    11: [5, [4]],
    12: [5, [6]],
    13: [5, [7]],
    14: [5, [8]],
    15: [5, [9]],
    16: [5, [10]],
    17: [5, [11]],
    18: [5, [12]],
    19: [5, [13]],
    20: [5, [14]],
    22: [5, [18]],
    23: [5, [19]],
    24: [5, [20]],
    25: [5, [32]],
    26: [5, [32, 544]],
    27: [5, [32, 545]],
    28: [5, [32, 546]],
    29: [5, [32, 547]],
    30: [5, [32, 548]],
    31: [5, [32, 549]],
    32: [5, [32, 550]],
    33: [5, [32, 551]],
    34: [5, [32, 552]],
    45: [5, [64, 10]],
    46: [5, [64, 21]],
    47: [5, [64, 14]],
    48: [5, [15]],
    49: [5, [1000]],
    50: [5, [32, 557]],
    51: [5, [32, 558]],
    52: [5, [32, 559]],
    53: [5, [32, 560]],
    54: [5, [32, 561]],
    55: [5, [32, 562]],
}

_WELL_KNOWN_DOMAIN_RIDS = {
    35: 512,
    36: 513,
    37: 514,
    38: 515,
    39: 516,
    40: 517,
    41: 518,
    42: 519,
    43: 520,
    44: 553,
}

def _sid_bytes(authority, subauthorities):
    builder = binary.builder(capacity = 8 + len(subauthorities) * 4)
    builder.u8(1)
    builder.u8(len(subauthorities))
    for shift in [40, 32, 24, 16, 8, 0]:
        builder.u8((authority >> shift) & 0xff)
    for value in subauthorities:
        builder.u32le(value)
    return builder.bytes()

def netapi_plugin(user_name = "Administrator", user_sid = [21, 1, 2, 3, 500], product_type = "WinNT", domain = "", accounts = None):
    """Models local group membership over the emulated account database."""
    accounts = accounts if accounts != None else {}
    state = {"actions": [], "allocations": {}, "accounts": accounts, "next_group_rid": 1000}
    signatures = {
        "dsrolefreememory": 1,
        "dsrolegetprimarydomaininformation": 3,
        "netapibufferfree": 1,
        "netlocalgroupadd": 4,
        "netlocalgroupgetmembers": 8,
    }

    def callback(event):
        name = event.name.lower()
        args = event.args
        machine = event.machine
        if name in ["netapibufferfree", "dsrolefreememory"]:
            if args[0] in state["allocations"]:
                state["allocations"].pop(args[0])
                machine.free(args[0])
            return 0
        if name == "dsrolegetprimarydomaininformation":
            if args[1] != 1 or not args[2]:
                return 124  # ERROR_INVALID_LEVEL
            domain_data = binary.encode(domain, encoding = "utf16le", nul = True) if domain else b""
            size = 36 + len(domain_data)
            address = machine.allocate(size = size, name = "DSROLE_PRIMARY_DOMAIN_INFO_BASIC")
            state["allocations"][address] = size
            server = product_type.lower() != "winnt"
            role = (3 if server else 1) if domain else (2 if server else 0)
            record = binary.builder(capacity = 36)
            record.u32le(role)
            record.u32le(0)
            record.u32le(address + 36 if domain_data else 0)
            record.u32le(0)
            record.u32le(0)
            record.reserve(16)
            machine.write(address, record.bytes())
            if domain_data:
                machine.write(address + 36, domain_data)
            machine.write_u32le(args[2], address)
            if len(state["actions"]) < 256:
                state["actions"].append({"api": name, "level": args[1], "role": role, "domain": domain})
            return 0
        if name == "netlocalgroupadd":
            if args[1] not in [0, 1] or not args[2]:
                if args[3]:
                    machine.write_u32le(args[3], 0)
                return 124 if args[1] not in [0, 1] else 87
            name_address = machine.read_u32le(args[2])
            group = machine.read_cstring(name_address, encoding = "utf16le") if name_address else ""
            if not group:
                if args[3]:
                    machine.write_u32le(args[3], 0)
                return 87
            identity = group.lower()
            if identity in accounts:
                return 2223  # NERR_GroupExists
            domain_sid = list(user_sid[:-1]) if len(user_sid) > 1 else [21, 1, 2, 3]
            rid = state["next_group_rid"]
            state["next_group_rid"] = rid + 1
            accounts[identity] = {
                "name": group,
                "domain": domain,
                "sid": "S-1-5-" + "-".join([str(part) for part in domain_sid + [rid]]),
                "use": 4,
            }
            if len(state["actions"]) < 256:
                state["actions"].append({"api": name, "group": group, "level": args[1], "rid": rid, "return": event.return_address})
            return 0
        group = machine.read_cstring(args[1], encoding = "utf16le") if args[1] else ""
        if len(state["actions"]) < 256:
            state["actions"].append({
                "api": name,
                "group": group,
                "level": args[2],
                "preferred_length": args[4],
                "return": event.return_address,
            })
        if not args[3] or not args[5] or not args[6]:
            return 87
        group_name = group.lower()
        builtins = [
            "administrators", "users", "guests", "power users", "account operators",
            "server operators", "print operators", "backup operators", "replicator",
        ]
        if group_name not in builtins:
            return 2220
        level = args[2]
        if level not in [0, 1, 2, 3]:
            return 124
        if group_name != "administrators":
            machine.write_u32le(args[3], 0)
            machine.write_u32le(args[5], 0)
            machine.write_u32le(args[6], 0)
            if args[7]:
                machine.write_u32le(args[7], 0)
            return 0
        member_sid = _sid_bytes(5, user_sid)
        member_name = binary.encode(user_name, encoding = "utf16le", nul = True)
        if level == 0:
            record_size, sid_offset, name_offset = 4, 4, 0
        elif level in [1, 2]:
            record_size, sid_offset, name_offset = 12, 12, 12 + len(member_sid)
        else:
            record_size, sid_offset, name_offset = 4, 0, 4
        required = record_size + (len(member_sid) if sid_offset else 0) + (len(member_name) if name_offset else 0)
        machine.write_u32le(args[6], 1)
        if args[7]:
            machine.write_u32le(args[7], 0)
        if args[4] != 0xffffffff and args[4] < required:
            machine.write_u32le(args[3], 0)
            machine.write_u32le(args[5], 0)
            return 234
        address = machine.allocate(size = required, name = "NetLocalGroupGetMembers")
        record = binary.builder(capacity = record_size)
        if level == 0:
            record.u32le(address + sid_offset)
        elif level in [1, 2]:
            record.u32le(address + sid_offset)
            record.u32le(1)
            record.u32le(address + name_offset)
        else:
            record.u32le(address + name_offset)
        machine.write(address, record.bytes())
        if sid_offset:
            machine.write(address + sid_offset, member_sid)
        if name_offset:
            machine.write(address + name_offset, member_name)
        machine.write_u32le(args[3], address)
        machine.write_u32le(args[5], 1)
        return 0

    def install(machine):
        for imported in machine.imports:
            name = imported.name.lower()
            if imported.module.lower() == "netapi32.dll" and name in signatures:
                machine.hook(callback, address = imported.address, argc = signatures[name])
        for name, argc in signatures.items():
            machine.provide_export(callback, module = "netapi32.dll", name = name, argc = argc)
    return emulator.plugin(install, name = "windows.netapi", state = state)

_WS2HELP_SIGNATURES = {
    "wahcreatehandlecontexttable": 1,
    "wahdestroyhandlecontexttable": 1,
    "wahopenapchelper": 1,
    "wahcloseapchelper": 1,
    "wahopencurrentthread": 2,
    "wahclosethread": 1,
}

def winsock_helper_plugin():
    """Models opaque Winsock handle-context tables used by ws2_32."""
    state = {"next_handle": 0x59000, "handles": {}}

    def callback(event):
        name = event.name.lower()
        if name in ["wahcreatehandlecontexttable", "wahopenapchelper"]:
            if not event.args[0]:
                return 87  # ERROR_INVALID_PARAMETER
            handle = state["next_handle"]
            state["next_handle"] += 1
            state["handles"][handle] = name
            event.machine.write_u32le(event.args[0], handle)
            return 0
        if name == "wahopencurrentthread":
            if event.args[0] not in state["handles"] or not event.args[1]:
                return 6 if event.args[0] not in state["handles"] else 87
            state["handles"][event.args[1]] = name
            return 0
        if event.args[0] not in state["handles"]:
            return 6  # ERROR_INVALID_HANDLE
        state["handles"].pop(event.args[0])
        return 0

    def install(machine):
        for imported in machine.imports:
            name = imported.name.lower()
            if imported.module.lower() == "ws2help.dll" and name in _WS2HELP_SIGNATURES:
                machine.hook(callback, address = imported.address, argc = _WS2HELP_SIGNATURES[name])

    return emulator.plugin(install, name = "windows.ws2help", state = state)

_WINSOCK_ORDINAL_SIGNATURES = {
    8: 1,   # htonl
    9: 1,   # htons
    14: 1,  # ntohl
    15: 1,  # ntohs
    111: 0, # WSAGetLastError
    112: 1, # WSASetLastError
    114: 0, # WSAIsBlocking
    115: 2, # WSAStartup
    116: 0, # WSACleanup
}

def winsock_plugin():
    """Models stable Winsock 1.1 ordinals shared by wsock32 and ws2_32."""
    state = {"last_error": 0, "started": False}

    def callback(event):
        if event.name == "#111":
            return state["last_error"]
        if event.name == "#112":
            state["last_error"] = event.args[0]
            return 0
        if event.name == "#114":
            return 0
        if event.name == "#115":
            requested = event.args[0]
            if not event.args[1]:
                state["last_error"] = 10014  # WSAEFAULT
                return 10014
            # WSADATA begins with negotiated/requested WORD versions followed
            # by the implementation description fields. The legacy clients in
            # scope inspect this fixed WinSock 1.1 prefix only.
            event.machine.write_u16le(event.args[1], requested)
            event.machine.write_u16le(event.args[1] + 2, 0x0101)
            event.machine.write(event.args[1] + 4, b"TinyRangeX WinSock 1.1\x00")
            state["started"] = True
            state["last_error"] = 0
            return 0
        if event.name == "#116":
            state["started"] = False
            state["last_error"] = 0
            return 0
        value = event.args[0]
        if event.name in ["#8", "#14"]:
            return (
                ((value & 0x000000ff) << 24) |
                ((value & 0x0000ff00) << 8) |
                ((value & 0x00ff0000) >> 8) |
                ((value & 0xff000000) >> 24)
            )
        return ((value & 0x00ff) << 8) | ((value & 0xff00) >> 8)

    def install(machine):
        for ordinal, argc in _WINSOCK_ORDINAL_SIGNATURES.items():
            for module in ["wsock32.dll", "ws2_32.dll"]:
                machine.provide_export(callback, module = module, ordinal = ordinal, argc = argc)
    return emulator.plugin(install, name = "windows.winsock", state = state)

def _map_generic_access(mask, mapping):
    """Expands Win32 generic access bits through a GENERIC_MAPPING."""
    value = mask & 0xffffffff
    generic = [0x80000000, 0x40000000, 0x20000000, 0x10000000]
    for index, bit in enumerate(generic):
        if value & bit:
            value = (value & ~bit) | mapping[index]
    return value & 0xffffffff

def _security_provider_module(name):
    normalized = name.replace("/", "\\").split("\\")[-1].lower()
    return normalized in ["advapi32.dll", "ntdll.dll"] or normalized.startswith("api-ms-win-security-") or normalized.startswith("ext-ms-win-security-")

def security_plugin(user_name = "Administrator", user_sid = [21, 1, 2, 3, 500], kernel = None, object_security = None, accounts = None):
    """Models an elevated interactive token for setup-time Win32 checks."""
    accounts = accounts if accounts != None else {}
    state = {"actions": []}

    def set_last_error(value):
        if kernel != None:
            kernel.state["last_error"] = value
    signatures = {
        "addaccessallowedace": 4,
        "addaccessallowedaceex": 5,
        "addaccessdeniedace": 4,
        "addaccessdeniedaceex": 5,
        "addace": 5,
        "adjusttokenprivileges": 6,
        "accesscheck": 8,
        "allocateandinitializesid": 11,
        "checktokenmembership": 3,
        "convertstringsecuritydescriptortosecuritydescriptora": 4,
        "convertstringsecuritydescriptortosecuritydescriptorw": 4,
        "convertstringsidtosida": 2,
        "convertstringsidtosidw": 2,
        "convertsidtostringsida": 2,
        "convertsidtostringsidw": 2,
        "copysid": 3,
        "createwellknownsid": 4,
        "equalsid": 2,
        "freesid": 1,
        "getlengthsid": 1,
        "getaclinformation": 4,
        "getace": 3,
        "getsecuritydescriptorlength": 1,
        "getsecuritydescriptorcontrol": 3,
        "getsecuritydescriptordacl": 4,
        "getsecuritydescriptorgroup": 3,
        "getsecuritydescriptorowner": 3,
        "getsecuritydescriptorsacl": 4,
        "getsididentifierauthority": 1,
        "getsidsubauthority": 2,
        "getsidsubauthoritycount": 1,
        "gettokeninformation": 5,
        "getfilesecuritya": 5,
        "getfilesecurityw": 5,
        "getusernamea": 2,
        "getusernamew": 2,
        "initializeacl": 3,
        "initializesecuritydescriptor": 2,
        "impersonateloggedonuser": 1,
        "isvalidsecuritydescriptor": 1,
        "isvalidacl": 1,
        "isvalidsid": 1,
        "lookupprivilegevaluew": 3,
        "lsafreememory": 1,
        "lookupaccountnamea": 7,
        "lookupaccountnamew": 7,
        "lookupaccountsida": 7,
        "lookupaccountsidw": 7,
        "makeabsolutesd": _MAKE_ABSOLUTE_SD_ARGUMENTS,
        "makeselfrelativesd": 3,
        "ntsetsecurityobject": 3,
        "ntopenprocess": 4,
        "ntopenprocesstoken": 3,
        "ntadjustprivilegestoken": 6,
        "ntcloseobjectauditalarm": 3,
        "ntqueryinformationtoken": 5,
        "ntsetinformationtoken": 4,
        "openprocesstoken": 3,
        "openthreadtoken": 4,
        "privilegecheck": 3,
        "reverttoself": 0,
        "rtlconvertsidtounicodestring": 3,
        "rtladdaccessallowedace": 4,
        "rtlallocateandinitializesid": 11,
        "rtlareallaccessesgranted": 2,
        "rtlareanyaccessesgranted": 2,
        "rtlcopysid": 3,
        "rtlcopyluid": 2,
        "rtlcreateacl": 3,
        "rtlcreatesecuritydescriptor": 2,
        "rtlequalsid": 2,
        "rtlfreeunicodestring": 1,
        "rtlfreesid": 1,
        "rtlgetace": 3,
        "rtlidentifierauthoritysid": 1,
        "rtlinitializesid": 3,
        "rtllengthsid": 1,
        "rtllengthrequiredsid": 1,
        "rtllengthsecuritydescriptor": 1,
        "rtlmapgenericmask": 2,
        "rtlnewsecurityobject": 6,
        "rtlsetdaclsecuritydescriptor": 4,
        "rtlsetgroupsecuritydescriptor": 3,
        "rtlsetownersecuritydescriptor": 3,
        "rtlsetsaclsecuritydescriptor": 4,
        "rtlsubauthoritycountsid": 1,
        "rtlsubauthoritysid": 2,
        "rtlvalidsid": 1,
        "setsecuritydescriptordacl": 4,
        "setsecuritydescriptorgroup": 3,
        "setsecuritydescriptorowner": 3,
        "setsecuritydescriptorsacl": 4,
        "setsecurityinfo": 7,
        "setfilesecuritya": 3,
        "setfilesecurityw": 3,
        "setthreadtoken": 2,
        "systemfunction004": 3,
        "systemfunction005": 3,
    }

    def sid(authority, subauthorities):
        return _sid_bytes(authority, subauthorities)

    def parse_sid(value):
        parts = value.strip().split("-")
        if len(parts) < 3 or parts[0].upper() != "S":
            return None
        revision = int(parts[1])
        authority = int(parts[2])
        subauthorities = [int(part) for part in parts[3:]]
        if revision != 1 or authority < 0 or authority >= 1 << 48 or len(subauthorities) > 15:
            return None
        for part in subauthorities:
            if part < 0 or part > 0xffffffff:
                return None
        return sid(authority, subauthorities)

    def local_allocation(machine, value, name):
        address = machine.allocate(value = value, name = name)
        if kernel != None:
            kernel.state["local_allocations"][address] = len(value)
        return address

    def sid_length(machine, address):
        return 8 + machine.read_u8(address + 1) * 4

    def sid_text(machine, address):
        header = binary.cursor(machine.read(address, 8))
        revision = header.u8()
        count = header.u8()
        authority = (header.u16be() << 32) | header.u32be()
        values = []
        cursor = binary.cursor(machine.read(address + 8, count * 4))
        for unused in range(count):
            values.append(str(cursor.u32le()))
        suffix = "-" + "-".join(values) if values else ""
        return "S-{}-{}{}".format(revision, authority, suffix)

    def sid_parts(machine, address):
        header = binary.cursor(machine.read(address, 8))
        revision = header.u8()
        count = header.u8()
        authority = (header.u16be() << 32) | header.u32be()
        values = []
        cursor = binary.cursor(machine.read(address + 8, count * 4))
        for unused in range(count):
            values.append(cursor.u32le())
        return [revision, authority, values]

    def acl_used(machine, address):
        header = binary.cursor(machine.read(address, 8))
        header.u8()
        header.u8()
        size = header.u16le()
        count = header.u16le()
        cursor = 8
        for unused in range(count):
            ace = binary.cursor(machine.read(address + cursor, 4))
            ace.u8()
            ace.u8()
            ace_size = ace.u16le()
            if ace_size < 8 or cursor + ace_size > size:
                return size
            cursor += ace_size
        return cursor

    def append_access_ace(machine, acl, ace_type, flags, access_mask, sid_address):
        if not acl or not sid_address:
            set_last_error(87)
            return 0
        sid_size = sid_length(machine, sid_address)
        used = acl_used(machine, acl)
        capacity = machine.read_u16le(acl + 2)
        ace_size = 8 + sid_size
        if used + ace_size > capacity:
            set_last_error(122)
            return 0
        ace = binary.builder(capacity = 8)
        ace.u8(ace_type)
        ace.u8(flags)
        ace.u16le(ace_size)
        ace.u32le(access_mask)
        machine.write(acl + used, ace.bytes())
        machine.write(acl + used + 8, machine.read(sid_address, sid_size))
        count = machine.read_u16le(acl + 4)
        machine.write_u16le(acl + 4, count + 1)
        set_last_error(0)
        return 1

    def set_descriptor_pointer(machine, address, offset, pointer, present, defaulted):
        control = machine.read_u16le(address + 2)
        present_mask = 0x10 if offset == 12 else (0x4 if offset == 16 else 0)
        defaulted_mask = {4: 0x1, 8: 0x2, 12: 0x20, 16: 0x8}.get(offset, 0)
        control = (control | present_mask) if present else (control & ~present_mask)
        control = (control | defaulted_mask) if defaulted else (control & ~defaulted_mask)
        machine.write_u16le(address + 2, control)
        machine.write_u32le(address + offset, pointer if present else 0)

    def descriptor_pointer(machine, address, offset):
        control = machine.read_u16le(address + 2)
        value = machine.read_u32le(address + offset)
        return address + value if value and control & 0x8000 else value

    def descriptor_length(machine, address):
        control = machine.read_u16le(address + 2)
        relative = bool(control & 0x8000)
        total = 20
        for offset in [4, 8, 12, 16]:
            raw = machine.read_u32le(address + offset)
            if not raw:
                continue
            pointer = address + raw if relative else raw
            if offset in [4, 8]:
                size = sid_length(machine, pointer)
            else:
                size = machine.read_u16le(pointer + 2)
            total = max(total, raw + size) if relative else total + size
        return total

    def relative_descriptor(machine, security_information, owner, group, dacl, sacl, default_owner = b"", default_group = b""):
        def sid_data(address):
            return machine.read(address, sid_length(machine, address)) if address else b""
        def acl_data(address):
            if not address:
                return b""
            size = machine.read_u16le(address + 2)
            return machine.read(address, size) if size >= 8 else b""

        owner_data = sid_data(owner) if security_information & 0x1 else default_owner
        group_data = sid_data(group) if security_information & 0x2 else default_group
        dacl_data = acl_data(dacl) if security_information & 0x4 else b""
        sacl_data = acl_data(sacl) if security_information & 0x8 else b""
        offset = 20
        owner_offset = offset if owner_data else 0
        offset += len(owner_data)
        group_offset = offset if group_data else 0
        offset += len(group_data)
        sacl_offset = offset if sacl_data else 0
        offset += len(sacl_data)
        dacl_offset = offset if dacl_data else 0
        control = 0x8000
        if security_information & 0x4:
            control |= 0x0004
        if security_information & 0x8:
            control |= 0x0010
        output = binary.builder(capacity = offset + len(dacl_data))
        output.u8(1)
        output.u8(0)
        output.u16le(control)
        output.u32le(owner_offset)
        output.u32le(group_offset)
        output.u32le(sacl_offset)
        output.u32le(dacl_offset)
        output.append(owner_data)
        output.append(group_data)
        output.append(sacl_data)
        output.append(dacl_data)
        return output.bytes()

    def access_ace(machine, address, ace_type, ace_size):
        if ace_size < 8:
            return None
        sid_offset = 8
        if ace_type in [5, 6, 7, 8]:
            if ace_size < 12:
                return None
            flags = machine.read_u32le(address + 8)
            sid_offset = 12
            if flags & 0x1:
                sid_offset += 16
            if flags & 0x2:
                sid_offset += 16
        if sid_offset + 8 > ace_size:
            return None
        sid_address = address + sid_offset
        size = sid_length(machine, sid_address)
        if sid_offset + size > ace_size:
            return None
        mask = machine.read_u32le(address + 4)
        return [mask, sid_text(machine, sid_address)]

    def check_dacl(machine, descriptor, desired_access, mapping, identities):
        control = machine.read_u16le(descriptor + 2)
        maximum_allowed = bool(desired_access & 0x02000000)
        requested = _map_generic_access(desired_access & ~0x02000000, mapping)
        full_access = (mapping[3] | 0x001f0000) & 0xffffffff
        if not control & 0x0004:
            return [True, (requested | (full_access if maximum_allowed else 0)) & 0xffffffff]
        acl = descriptor_pointer(machine, descriptor, 16)
        if not acl:
            return [True, (requested | (full_access if maximum_allowed else 0)) & 0xffffffff]

        header = binary.cursor(machine.read(acl, 8))
        revision = header.u8()
        header.u8()
        size = header.u16le()
        count = header.u16le()
        header.u16le()
        if revision not in [2, 4] or size < 8:
            return None

        granted = 0
        denied = 0
        offset = 8
        for unused in range(count):
            if offset + 4 > size:
                return None
            ace_header = binary.cursor(machine.read(acl + offset, 4))
            ace_type = ace_header.u8()
            ace_flags = ace_header.u8()
            ace_size = ace_header.u16le()
            if ace_size < 8 or offset + ace_size > size:
                return None
            # INHERIT_ONLY_ACE does not apply to the object protected by this ACL.
            if not ace_flags & 0x08 and ace_type in [0, 1, 5, 6]:
                ace = access_ace(machine, acl + offset, ace_type, ace_size)
                if ace == None:
                    return None
                mask, trustee = ace
                if trustee in identities:
                    mapped = _map_generic_access(mask, mapping)
                    if ace_type in [1, 6]:
                        denied |= mapped
                    else:
                        granted |= mapped & ~denied
            offset += ace_size

        effective = granted & 0xffffffff
        allowed = requested & ~effective == 0
        return [allowed, effective if maximum_allowed else (requested & effective)]

    def token_information(machine, kind, address, capacity, required_address):
        if not required_address:
            set_last_error(87)
            return 0
        token_sid = sid(5, [32, 544]) if kind == 2 else sid(5, user_sid)
        header_size = 12 if kind == 2 else 8
        required = header_size + len(token_sid)
        machine.write_u32le(required_address, required)
        if address == 0 or capacity < required:
            set_last_error(122)
            return 0
        machine.write(address, b"\x00" * required)
        sid_address = address + header_size
        if kind == 2:  # TokenGroups
            machine.write_u32le(address, 1)
            machine.write_u32le(address + 4, sid_address)
            machine.write_u32le(address + 8, 4)
        else:  # TokenUser and bounded fallbacks
            machine.write_u32le(address, sid_address)
        machine.write(sid_address, token_sid)
        set_last_error(0)
        return 1

    def account_for_sid(value):
        known = {
            "S-1-1-0": ["Everyone", "NT AUTHORITY", 5],
            "S-1-5-11": ["Authenticated Users", "NT AUTHORITY", 5],
            "S-1-5-18": ["SYSTEM", "NT AUTHORITY", 5],
            "S-1-5-19": ["LOCAL SERVICE", "NT AUTHORITY", 5],
            "S-1-5-20": ["NETWORK SERVICE", "NT AUTHORITY", 5],
            "S-1-5-32-544": ["Administrators", "BUILTIN", 4],
            "S-1-5-32-545": ["Users", "BUILTIN", 4],
            "S-1-5-32-546": ["Guests", "BUILTIN", 4],
            "S-1-5-32-547": ["Power Users", "BUILTIN", 4],
            "S-1-5-32-548": ["Account Operators", "BUILTIN", 4],
            "S-1-5-32-549": ["Server Operators", "BUILTIN", 4],
            "S-1-5-32-550": ["Print Operators", "BUILTIN", 4],
            "S-1-5-32-551": ["Backup Operators", "BUILTIN", 4],
            "S-1-5-32-552": ["Replicator", "BUILTIN", 4],
        }
        administrator = "S-1-5-" + "-".join([str(part) for part in user_sid])
        if value == administrator:
            return [user_name, "", 1]
        return known.get(value)

    def sid_for_account(value):
        normalized = value.replace("/", "\\").lower()
        name = normalized.split("\\")[-1]
        dynamic = accounts.get(name)
        if dynamic != None:
            return [dynamic["sid"], dynamic["domain"], dynamic["use"]]
        known = {
            "everyone": ["S-1-1-0", "NT AUTHORITY", 5],
            "authenticated users": ["S-1-5-11", "NT AUTHORITY", 5],
            "system": ["S-1-5-18", "NT AUTHORITY", 5],
            "local service": ["S-1-5-19", "NT AUTHORITY", 5],
            "network service": ["S-1-5-20", "NT AUTHORITY", 5],
            "administrators": ["S-1-5-32-544", "BUILTIN", 4],
            "users": ["S-1-5-32-545", "BUILTIN", 4],
            "guests": ["S-1-5-32-546", "BUILTIN", 4],
            "power users": ["S-1-5-32-547", "BUILTIN", 4],
            "account operators": ["S-1-5-32-548", "BUILTIN", 4],
            "server operators": ["S-1-5-32-549", "BUILTIN", 4],
            "print operators": ["S-1-5-32-550", "BUILTIN", 4],
            "backup operators": ["S-1-5-32-551", "BUILTIN", 4],
            "replicator": ["S-1-5-32-552", "BUILTIN", 4],
        }
        if name == user_name.lower():
            return ["S-1-5-" + "-".join([str(part) for part in user_sid]), "", 1]
        return known.get(name)

    def callback(event):
        name = event.name.lower()
        args = event.args
        machine = event.machine
        action = {"api": name, "args": list(args), "return": event.return_address}
        if name in ["setsecuritydescriptorowner", "setsecuritydescriptorgroup"] and args[1]:
            action["sid"] = sid_text(machine, args[1])
        if name in ["lookupaccountnamea", "lookupaccountnamew"] and args[1]:
            action["account"] = machine.read_cstring(args[1], encoding = "utf16le" if name.endswith("w") else "ascii")
        state["actions"].append(action)
        if name == "rtlareallaccessesgranted":
            return 1 if args[0] & args[1] == args[0] else 0
        if name == "rtlareanyaccessesgranted":
            return 1 if args[0] & args[1] else 0
        if name == "rtlmapgenericmask":
            if not args[0] or not args[1]:
                return None
            mapping = binary.cursor(machine.read(args[1], 16))
            access = machine.read_u32le(args[0])
            machine.write_u32le(args[0], _map_generic_access(access, [mapping.u32le(), mapping.u32le(), mapping.u32le(), mapping.u32le()]))
            return None
        if name in ["systemfunction004", "systemfunction005"]:
            if not args[0] or not args[1] or not args[2]:
                return 0xc000000d
            action["source_descriptor"] = machine.read(args[0], 12)
            action["key_descriptor"] = machine.read(args[1], 12)
            action["destination_descriptor"] = machine.read(args[2], 12)
            source = binary.cursor(machine.read(args[0], 12))
            source_length = source.u32le()
            source.u32le()
            source_address = source.u32le()
            key = binary.cursor(machine.read(args[1], 12))
            key_length = key.u32le()
            key.u32le()
            key_address = key.u32le()
            destination = binary.cursor(machine.read(args[2], 12))
            destination.u32le()
            destination_capacity = destination.u32le()
            destination_address = destination.u32le()
            if not source_address or not key_address or key_length < 7:
                return 0xc000000d
            key_data = machine.read(key_address, key_length)
            if name == "systemfunction004":
                output_length = (source_length + 15) & ~7
                if destination_address and destination_capacity < output_length:
                    machine.write_u32le(args[2], output_length)
                    return 0xc0000023
                plain = binary.builder(capacity = output_length)
                plain.u32le(source_length)
                plain.u32le(1)
                plain.append(machine.read(source_address, source_length))
                plain.reserve(output_length - plain.size)
                output = legacy_lsa_secret_crypt(key_data, plain.bytes())
            else:
                if source_length < 8 or source_length % 8:
                    return 0xc000000d
                plain = legacy_lsa_secret_crypt(key_data, machine.read(source_address, source_length), decrypt = True)
                header = binary.cursor(plain)
                output_length = header.u32le()
                if header.u32le() != 1 or output_length > header.remaining:
                    return 0xc000000d
                if destination_address and destination_capacity < output_length:
                    machine.write_u32le(args[2], output_length)
                    return 0xc0000023
                output = header.bytes(output_length)
            if not destination_address:
                destination_address = machine.allocate(size = max(1, len(output)), name = name)
                destination_capacity = len(output)
                machine.write_u32le(args[2] + 4, destination_capacity)
                machine.write_u32le(args[2] + 8, destination_address)
            machine.write(destination_address, output)
            machine.write_u32le(args[2], output_length)
            return 0
        if name == "accesscheck":
            if not args[0] or not args[1] or not args[3] or not args[5] or not args[6] or not args[7]:
                set_last_error(87)
                return 0
            mapping_cursor = binary.cursor(machine.read(args[3], 16))
            mapping = [mapping_cursor.u32le(), mapping_cursor.u32le(), mapping_cursor.u32le(), mapping_cursor.u32le()]
            privilege_capacity = machine.read_u32le(args[5])
            machine.write_u32le(args[5], 8)
            if not args[4] or privilege_capacity < 8:
                set_last_error(122)
                return 0
            machine.write(args[4], b"\x00" * 8)
            administrator = "S-1-5-" + "-".join([str(part) for part in user_sid])
            identities = [administrator, "S-1-1-0", "S-1-5-11", "S-1-5-32-544"]
            result = check_dacl(machine, args[0], args[2], mapping, identities)
            if result == None:
                set_last_error(1336)  # ERROR_INVALID_ACL
                return 0
            allowed, granted = result
            machine.write_u32le(args[6], granted)
            machine.write_u32le(args[7], 1 if allowed else 0)
            set_last_error(0 if allowed else 5)
            return 1
        if name == "setsecurityinfo":
            if object_security == None:
                return 6  # ERROR_INVALID_HANDLE
            registry_owner = _sid_bytes(5, [32, 544]) if args[1] == 4 else b""
            descriptor = relative_descriptor(
                machine,
                args[2],
                args[3],
                args[4],
                args[5],
                args[6],
                default_owner = registry_owner,
                default_group = registry_owner,
            )
            action["object_type"] = args[1]
            action["security_information"] = args[2]
            action["descriptor"] = descriptor
            return object_security(args[0], descriptor) if args[1] == 4 else 6
        if name == "ntsetsecurityobject":
            if object_security == None or not args[2]:
                return 0xc0000008  # STATUS_INVALID_HANDLE
            descriptor = relative_descriptor(
                machine,
                args[1],
                descriptor_pointer(machine, args[2], 4),
                descriptor_pointer(machine, args[2], 8),
                descriptor_pointer(machine, args[2], 16),
                descriptor_pointer(machine, args[2], 12),
            )
            action["security_information"] = args[1]
            action["descriptor"] = descriptor
            return 0 if object_security(args[0], descriptor) == 0 else 0xc0000008
        if name == "ntopenprocess":
            if not args[0]:
                return 0xc000000d
            machine.write_u32le(args[0], 2)
            return 0
        if name == "ntopenprocesstoken":
            if not args[2]:
                return 0xc000000d
            machine.write_u32le(args[2], 1)
            return 0
        if name == "ntadjustprivilegestoken":
            if args[5]:
                machine.write_u32le(args[5], 0)
            return 0
        if name == "ntcloseobjectauditalarm":
            return 0
        if name == "ntqueryinformationtoken":
            if not args[4]:
                return 0xc000000d
            if args[1] == 6:  # TokenStatistics in the NT 3.x ABI.
                required = 48
                machine.write_u32le(args[4], required)
                if not args[2] or args[3] < required:
                    return 0xc0000023  # STATUS_BUFFER_TOO_SMALL
                output = binary.builder(capacity = required)
                output.u64le(0x1000)  # TokenId
                output.u64le(0x3e7)   # SYSTEM authentication id
                output.u64le(0x7fffffffffffffff)
                output.u32le(1)       # TokenPrimary
                output.u32le(2)       # SecurityImpersonation
                output.u32le(0)
                output.u32le(0)
                output.u32le(0)
                output.u32le(0)
                machine.write(args[2], output.bytes())
                return 0
            return 0xc0000003  # STATUS_INVALID_INFO_CLASS
        if name == "ntsetinformationtoken":
            if not args[0] or not args[2]:
                return 0xc000000d
            return 0
        if name == "lsafreememory":
            return 0
        if name == "rtlnewsecurityobject":
            source = args[1] if args[1] else args[0]
            if not source or not args[2]:
                return 0xc000000d
            descriptor = relative_descriptor(
                machine,
                0x0f,
                descriptor_pointer(machine, source, 4),
                descriptor_pointer(machine, source, 8),
                descriptor_pointer(machine, source, 16),
                descriptor_pointer(machine, source, 12),
            )
            address = machine.allocate(value = descriptor, name = "RtlNewSecurityObject")
            machine.write_u32le(args[2], address)
            return 0
        if name in ["openprocesstoken", "openthreadtoken"]:
            machine.write_u32le(args[2] if name == "openprocesstoken" else args[3], 1)
            return 1
        if name == "reverttoself":
            return 1
        if name == "impersonateloggedonuser":
            return 1 if args[0] else 0
        if name in ["convertstringsecuritydescriptortosecuritydescriptora", "convertstringsecuritydescriptortosecuritydescriptorw"]:
            if args[1] != 1 or not args[0] or not args[2]:
                return 0
            value = machine.read_cstring(args[0], encoding = "utf16le" if name.endswith("w") else "ascii")
            administrator = "S-1-5-" + "-".join([str(part) for part in user_sid])
            descriptor = _sddl_descriptor(value, aliases = {"LA": administrator})
            address = local_allocation(machine, descriptor, "self-relative security descriptor")
            machine.write_u32le(args[2], address)
            if args[3]:
                machine.write_u32le(args[3], len(descriptor))
            return 1
        if name in ["convertstringsidtosida", "convertstringsidtosidw"]:
            if not args[0] or not args[1]:
                set_last_error(87)
                return 0
            value = machine.read_cstring(args[0], encoding = "utf16le" if name.endswith("w") else "ascii")
            parsed = parse_sid(value)
            if parsed == None:
                set_last_error(1337)  # ERROR_INVALID_SID
                return 0
            address = local_allocation(machine, parsed, "converted SID")
            machine.write_u32le(args[1], address)
            set_last_error(0)
            return 1
        if name in ["convertsidtostringsida", "convertsidtostringsidw"]:
            if not args[0] or not args[1]:
                set_last_error(87)
                return 0
            wide = name.endswith("w")
            value = binary.encode(sid_text(machine, args[0]), encoding = "utf16le" if wide else "ascii", nul = True)
            address = local_allocation(machine, value, "string SID")
            machine.write_u32le(args[1], address)
            set_last_error(0)
            return 1
        if name in ["getfilesecuritya", "getfilesecurityw"]:
            if kernel == None or not args[0] or not args[4]:
                set_last_error(87)
                return 0
            wide = name.endswith("w")
            path = _normalize_virtual_path(machine.read_cstring(args[0], encoding = "utf16le" if wide else "ascii"))
            entry = kernel.state["paths"].get(path)
            if entry == None:
                set_last_error(2)
                return 0
            descriptor = entry.get("security", _sddl_descriptor("O:SYG:SYD:(A;;GA;;;SY)(A;;GA;;;BA)"))
            machine.write_u32le(args[4], len(descriptor))
            state["actions"].append({"api": name, "path": path, "information": args[1], "size": len(descriptor)})
            if not args[2] or args[3] < len(descriptor):
                set_last_error(122)
                return 0
            machine.write(args[2], descriptor)
            set_last_error(0)
            return 1
        if name in ["setfilesecuritya", "setfilesecurityw"]:
            if kernel == None or not args[0] or not args[2]:
                set_last_error(87)
                return 0
            wide = name.endswith("w")
            path = _normalize_virtual_path(machine.read_cstring(args[0], encoding = "utf16le" if wide else "ascii"))
            entry = kernel.state["paths"].get(path)
            if entry == None:
                set_last_error(2)
                return 0
            # FAT has no persistent ACL stream. Preserve that the requested
            # information was applied without retaining caller-owned absolute
            # descriptor pointers after this call.
            entry["security_information"] = args[1]
            state["actions"].append({"api": name, "path": path, "information": args[1]})
            set_last_error(0)
            return 1
        if name == "gettokeninformation":
            return token_information(machine, args[1], args[2], args[3], args[4])
        if name in ["allocateandinitializesid", "rtlallocateandinitializesid"]:
            authority_cursor = binary.cursor(machine.read(args[0], 6))
            authority = (authority_cursor.u16be() << 32) | authority_cursor.u32be()
            value = sid(authority, args[2:2 + min(args[1], 8)])
            address = machine.allocate(size = len(value), value = value, name = "SID")
            machine.write_u32le(args[10], address)
            return 0 if name.startswith("rtl") else 1
        if name == "createwellknownsid":
            if not args[3]:
                set_last_error(87)
                return 0
            spec = _WELL_KNOWN_SIDS.get(args[0])
            if spec != None:
                value = sid(spec[0], spec[1])
            elif args[0] in _WELL_KNOWN_DOMAIN_RIDS and args[1]:
                revision, authority, values = sid_parts(machine, args[1])
                if revision != 1 or len(values) >= 15:
                    set_last_error(87)
                    return 0
                value = sid(authority, values + [_WELL_KNOWN_DOMAIN_RIDS[args[0]]])
            else:
                set_last_error(87)
                return 0
            capacity = machine.read_u32le(args[3])
            machine.write_u32le(args[3], len(value))
            if not args[2] or capacity < len(value):
                set_last_error(122)
                return 0
            machine.write(args[2], value)
            set_last_error(0)
            return 1
        if name == "getlengthsid":
            if not args[0]:
                set_last_error(87)
                return 0
            return sid_length(machine, args[0])
        if name == "rtllengthrequiredsid":
            return 8 + args[0] * 4
        if name == "rtlinitializesid":
            if not args[0] or not args[1] or args[2] > 15:
                return 0xc000000d
            header = binary.builder(capacity = 8)
            header.u8(1)
            header.u8(args[2])
            header.append(machine.read(args[1], 6))
            machine.write(args[0], header.bytes())
            return 0
        if name == "rtllengthsid":
            return sid_length(machine, args[0]) if args[0] else 0
        if name == "rtlvalidsid":
            return 1 if args[0] and machine.read_u8(args[0]) == 1 else 0
        if name == "rtlidentifierauthoritysid":
            return args[0] + 2 if args[0] else 0
        if name == "rtlsubauthoritycountsid":
            return args[0] + 1 if args[0] else 0
        if name == "rtlsubauthoritysid":
            return args[0] + 8 + args[1] * 4 if args[0] else 0
        if name == "rtlequalsid":
            if not args[0] or not args[1]:
                return 0
            left_length = sid_length(machine, args[0])
            right_length = sid_length(machine, args[1])
            return 1 if left_length == right_length and machine.read(args[0], left_length) == machine.read(args[1], right_length) else 0
        if name == "rtlcopysid":
            if not args[1] or not args[2]:
                return 0xc000000d
            length = sid_length(machine, args[2])
            if args[0] < length:
                return 0xc0000023
            machine.write(args[1], machine.read(args[2], length))
            return 0
        if name == "rtlcopyluid":
            if args[0] and args[1]:
                machine.write(args[0], machine.read(args[1], 8))
            return None
        if name == "copysid":
            if not args[2]:
                set_last_error(87)
                return 0
            length = sid_length(machine, args[2])
            if args[0] < length or not args[1]:
                set_last_error(122 if args[0] < length else 87)
                return 0
            machine.write(args[1], machine.read(args[2], length))
            set_last_error(0)
            return 1
        if name == "isvalidsid":
            return 1 if args[0] and machine.read_u8(args[0]) == 1 else 0
        if name == "getsididentifierauthority":
            return args[0] + 2 if args[0] else 0
        if name == "getsidsubauthoritycount":
            return args[0] + 1 if args[0] else 0
        if name == "getsidsubauthority":
            return args[0] + 8 + args[1] * 4 if args[0] else 0
        if name == "equalsid":
            if not args[0] or not args[1]:
                return 0
            left_length = sid_length(machine, args[0])
            right_length = sid_length(machine, args[1])
            return 1 if left_length == right_length and machine.read(args[0], left_length) == machine.read(args[1], right_length) else 0
        if name in ["freesid", "rtlfreesid"]:
            return 0
        if name == "lookupprivilegevaluew":
            machine.write(args[2], b"\x00" * 8)
            return 1
        if name in ["lookupaccountnamea", "lookupaccountnamew"]:
            if not args[1] or not args[3] or not args[5]:
                set_last_error(87)
                return 0
            wide = name.endswith("w")
            account_name = machine.read_cstring(args[1], encoding = "utf16le" if wide else "ascii")
            account = sid_for_account(account_name)
            if account == None:
                set_last_error(1332)  # ERROR_NONE_MAPPED
                return 0
            sid_value, domain, use = account
            parts = sid_value.split("-")
            sid_data = sid(int(parts[2]), [int(part) for part in parts[3:]])
            sid_capacity = machine.read_u32le(args[3])
            domain_capacity = machine.read_u32le(args[5])
            required_domain = len(domain) + 1
            if not args[2] or sid_capacity < len(sid_data) or not args[4] or domain_capacity < required_domain:
                machine.write_u32le(args[3], len(sid_data))
                machine.write_u32le(args[5], required_domain)
                set_last_error(122)  # ERROR_INSUFFICIENT_BUFFER
                return 0
            machine.write(args[2], sid_data)
            _write_string(machine, args[4], domain, wide)
            machine.write_u32le(args[3], len(sid_data))
            machine.write_u32le(args[5], len(domain))
            if args[6]:
                machine.write_u32le(args[6], use)
            set_last_error(0)
            return 1
        if name in ["lookupaccountsida", "lookupaccountsidw"]:
            if not args[1] or not args[3] or not args[5]:
                set_last_error(87)
                return 0
            account = account_for_sid(sid_text(machine, args[1]))
            if account == None:
                set_last_error(1332)
                return 0
            account_name, domain, use = account
            name_capacity = machine.read_u32le(args[3])
            domain_capacity = machine.read_u32le(args[5])
            required_name = len(account_name) + 1
            required_domain = len(domain) + 1
            if not args[2] or name_capacity < required_name or not args[4] or domain_capacity < required_domain:
                machine.write_u32le(args[3], required_name)
                machine.write_u32le(args[5], required_domain)
                set_last_error(122)
                return 0
            wide = name.endswith("w")
            _write_string(machine, args[2], account_name, wide)
            _write_string(machine, args[4], domain, wide)
            machine.write_u32le(args[3], len(account_name))
            machine.write_u32le(args[5], len(domain))
            if args[6]:
                machine.write_u32le(args[6], use)
            set_last_error(0)
            return 1
        if name == "adjusttokenprivileges":
            return 1
        if name == "privilegecheck":
            machine.write_u32le(args[2], 1)
            return 1
        if name == "checktokenmembership":
            machine.write_u32le(args[2], 1)
            return 1
        if name == "setthreadtoken":
            return 1
        if name in ["initializesecuritydescriptor", "rtlcreatesecuritydescriptor"]:
            machine.write(args[0], b"\x00" * 20)
            machine.write(args[0], bytes([args[1] & 0xff]))
            return 0 if name.startswith("rtl") else 1
        if name in ["initializeacl", "rtlcreateacl"]:
            if args[1] < 8:
                return 0xc0000023 if name.startswith("rtl") else 0
            machine.write(args[0], b"\x00" * args[1])
            machine.write(args[0], bytes([args[2] & 0xff]))
            machine.write_u16le(args[0] + 2, args[1])
            return 0 if name.startswith("rtl") else 1
        if name in ["addaccessallowedace", "addaccessdeniedace", "rtladdaccessallowedace"]:
            added = append_access_ace(machine, args[0], 0 if name != "addaccessdeniedace" else 1, 0, args[2], args[3])
            return (0 if added else 0xc0000077) if name.startswith("rtl") else added
        if name in ["addaccessallowedaceex", "addaccessdeniedaceex"]:
            return append_access_ace(machine, args[0], 0 if name == "addaccessallowedaceex" else 1, args[2], args[3], args[4])
        if name == "addace":
            if not args[0] or not args[3] or args[4] == 0:
                return 0
            header = binary.cursor(machine.read(args[0], 8))
            header.u8()
            header.u8()
            capacity = header.u16le()
            count = header.u16le()
            source_count = 0
            source_offset = 0
            while source_offset < args[4]:
                if source_offset + 4 > args[4]:
                    return 0
                source_header = binary.cursor(machine.read(args[3] + source_offset, 4))
                source_header.u8()
                source_header.u8()
                source_size = source_header.u16le()
                if source_size < 8 or source_offset + source_size > args[4]:
                    return 0
                source_count += 1
                source_offset += source_size
            if source_offset != args[4]:
                return 0
            used = acl_used(machine, args[0])
            if used + args[4] > capacity:
                return 0
            index = count if args[2] == 0xffffffff else args[2]
            if index > count:
                return 0
            insertion = 8
            for unused in range(index):
                ace = binary.cursor(machine.read(args[0] + insertion, 4))
                ace.u8()
                ace.u8()
                insertion += ace.u16le()
            tail = machine.read(args[0] + insertion, used - insertion)
            source = machine.read(args[3], args[4])
            machine.write(args[0] + insertion + args[4], tail)
            machine.write(args[0] + insertion, source)
            machine.write_u16le(args[0] + 4, count + source_count)
            return 1
        if name in ["setsecuritydescriptorowner", "rtlsetownersecuritydescriptor"]:
            set_descriptor_pointer(machine, args[0], 4, args[1], True, bool(args[2]))
            return 0 if name.startswith("rtl") else 1
        if name in ["setsecuritydescriptorgroup", "rtlsetgroupsecuritydescriptor"]:
            set_descriptor_pointer(machine, args[0], 8, args[1], True, bool(args[2]))
            return 0 if name.startswith("rtl") else 1
        if name in ["setsecuritydescriptorsacl", "rtlsetsaclsecuritydescriptor"]:
            set_descriptor_pointer(machine, args[0], 12, args[2], bool(args[1]), bool(args[3]))
            return 0 if name.startswith("rtl") else 1
        if name in ["setsecuritydescriptordacl", "rtlsetdaclsecuritydescriptor"]:
            set_descriptor_pointer(machine, args[0], 16, args[2], bool(args[1]), bool(args[3]))
            return 0 if name.startswith("rtl") else 1
        if name == "isvalidsecuritydescriptor":
            return 1 if args[0] and machine.read_u8(args[0]) == 1 else 0
        if name == "isvalidacl":
            if not args[0]:
                return 0
            header = binary.cursor(machine.read(args[0], 8))
            revision = header.u8()
            header.u8()
            size = header.u16le()
            count = header.u16le()
            header.u16le()
            if revision not in [2, 4] or size < 8:
                return 0
            offset = 8
            for unused in range(count):
                if offset + 4 > size:
                    return 0
                ace = binary.cursor(machine.read(args[0] + offset, 4))
                ace.u8()
                ace.u8()
                ace_size = ace.u16le()
                if ace_size < 8 or offset + ace_size > size:
                    return 0
                offset += ace_size
            return 1
        if name == "getaclinformation":
            if not args[0] or not args[1]:
                return 0
            header = binary.cursor(machine.read(args[0], 8))
            revision = header.u8()
            header.u8()
            size = header.u16le()
            count = header.u16le()
            header.u16le()
            if args[3] == 1:  # AclRevisionInformation
                if args[2] < 4:
                    return 0
                machine.write_u32le(args[1], revision)
                return 1
            if args[3] == 2:  # AclSizeInformation
                if args[2] < 12:
                    return 0
                used = acl_used(machine, args[0])
                machine.write_u32le(args[1], count)
                machine.write_u32le(args[1] + 4, used)
                machine.write_u32le(args[1] + 8, max(0, size - used))
                return 1
            return 0
        if name in ["getace", "rtlgetace"]:
            if not args[0] or not args[2]:
                return 0xc000000d if name.startswith("rtl") else 0
            header = binary.cursor(machine.read(args[0], 8))
            header.u8()
            header.u8()
            size = header.u16le()
            count = header.u16le()
            if args[1] >= count:
                return 0xc000000d if name.startswith("rtl") else 0
            offset = 8
            for index in range(count):
                ace = binary.cursor(machine.read(args[0] + offset, 4))
                ace.u8()
                ace.u8()
                ace_size = ace.u16le()
                if ace_size < 8 or offset + ace_size > size:
                    return 0
                if index == args[1]:
                    machine.write_u32le(args[2], args[0] + offset)
                    return 0 if name.startswith("rtl") else 1
                offset += ace_size
            return 0xc000000d if name.startswith("rtl") else 0
        if name in ["getsecuritydescriptorlength", "rtllengthsecuritydescriptor"]:
            return descriptor_length(machine, args[0]) if args[0] else 0
        if name == "getsecuritydescriptorcontrol":
            if not args[0] or not args[1] or not args[2]:
                set_last_error(87)
                return 0
            machine.write_u16le(args[1], machine.read_u16le(args[0] + 2))
            machine.write_u32le(args[2], machine.read_u8(args[0]))
            return 1
        if name in ["getsecuritydescriptorowner", "getsecuritydescriptorgroup"]:
            if not args[0] or not args[1] or not args[2]:
                set_last_error(87)
                return 0
            offset = 4 if name.endswith("owner") else 8
            control = machine.read_u16le(args[0] + 2)
            machine.write_u32le(args[1], descriptor_pointer(machine, args[0], offset))
            machine.write_u32le(args[2], 1 if control & (0x1 if offset == 4 else 0x2) else 0)
            return 1
        if name in ["getsecuritydescriptordacl", "getsecuritydescriptorsacl"]:
            if not args[0] or not args[1] or not args[2] or not args[3]:
                set_last_error(87)
                return 0
            offset = 16 if name.endswith("dacl") else 12
            control = machine.read_u16le(args[0] + 2)
            machine.write_u32le(args[1], 1 if control & (0x4 if offset == 16 else 0x10) else 0)
            machine.write_u32le(args[2], descriptor_pointer(machine, args[0], offset))
            machine.write_u32le(args[3], 1 if control & (0x8 if offset == 16 else 0x20) else 0)
            return 1
        if name == "makeabsolutesd":
            if not args[0]:
                return 0
            header = binary.cursor(machine.read(args[0], 20))
            revision = header.u8()
            header.u8()
            control = header.u16le()
            offsets = [header.u32le(), header.u32le(), header.u32le(), header.u32le()]
            parts = []
            for index, offset in enumerate(offsets):
                if not offset:
                    parts.append(b"")
                elif index < 2:
                    parts.append(machine.read(args[0] + offset, sid_length(machine, args[0] + offset)))
                else:
                    acl = args[0] + offset
                    size = machine.read_u16le(acl + 2)
                    parts.append(machine.read(acl, size))

            absolute_capacity = machine.read_u32le(args[2]) if args[2] else 0
            destinations = [args[7], args[9], args[5], args[3]]
            size_addresses = [args[8], args[10], args[6], args[4]]
            capacities = []
            for address in size_addresses:
                capacities.append(machine.read_u32le(address) if address else 0)
            if args[2]:
                machine.write_u32le(args[2], 20)
            for index, address in enumerate(size_addresses):
                if address:
                    machine.write_u32le(address, len(parts[index]))
            if not args[1] or absolute_capacity < 20:
                set_last_error(122)  # ERROR_INSUFFICIENT_BUFFER
                return 0
            for index, part in enumerate(parts):
                if part and (not destinations[index] or capacities[index] < len(part)):
                    set_last_error(122)
                    return 0
            descriptor = binary.builder(capacity = 20)
            descriptor.u8(revision)
            descriptor.u8(0)
            descriptor.u16le(control & ~0x8000)
            for index, part in enumerate(parts):
                descriptor.u32le(destinations[index] if part else 0)
                if part:
                    machine.write(destinations[index], part)
            machine.write(args[1], descriptor.bytes())
            return 1
        if name == "makeselfrelativesd":
            if not args[0] or not args[2]:
                return 0
            header = binary.cursor(machine.read(args[0], 20))
            revision = header.u8()
            header.u8()
            control = header.u16le() | 0x8000
            pointers = [header.u32le(), header.u32le(), header.u32le(), header.u32le()]
            parts = []
            for index, pointer in enumerate(pointers):
                if not pointer:
                    parts.append(b"")
                elif index < 2:
                    parts.append(machine.read(pointer, sid_length(machine, pointer)))
                else:
                    acl_size = machine.read_u16le(pointer + 2)
                    parts.append(machine.read(pointer, acl_size))
            required = 20
            for part in parts:
                required += len(part)
            capacity = machine.read_u32le(args[2])
            machine.write_u32le(args[2], required)
            if not args[1] or capacity < required:
                set_last_error(122)  # ERROR_INSUFFICIENT_BUFFER
                return 0
            offsets = []
            offset = 20
            for part in parts:
                offsets.append(offset if part else 0)
                offset += len(part)
            output = binary.builder(capacity = required)
            output.u8(revision)
            output.u8(0)
            output.u16le(control)
            for part_offset in offsets:
                output.u32le(part_offset)
            for part in parts:
                output.append(part)
            machine.write(args[1], output.bytes())
            return 1
        if name in ["getusernamea", "getusernamew"]:
            if not args[1]:
                set_last_error(87)
                return 0
            capacity = machine.read_u32le(args[1])
            value = user_name
            if capacity < len(value) + 1:
                machine.write_u32le(args[1], len(value) + 1)
                set_last_error(122)
                return 0
            if not args[0]:
                set_last_error(87)
                return 0
            _write_string(machine, args[0], value, name.endswith("w"), capacity)
            # GetUserName reports the terminating NUL in its successful size.
            machine.write_u32le(args[1], len(value) + 1)
            set_last_error(0)
            return 1
        if name == "rtlconvertsidtounicodestring":
            value = binary.encode(sid_text(machine, args[1]), encoding = "utf16le", nul = True)
            if args[2]:
                address = machine.allocate(size = len(value), value = value, name = "SID string")
            else:
                address = machine.read_u32le(args[0] + 4)
                capacity = machine.read_u16le(args[0] + 2)
                if capacity < len(value):
                    return 0xc0000023
                machine.write(address, value)
            length = len(value) - 2
            builder = binary.builder(capacity = 8)
            builder.u16le(length)
            builder.u16le(len(value))
            builder.u32le(address)
            machine.write(args[0], builder.bytes())
            return 0
        if name == "rtlfreeunicodestring":
            return None
        return 0

    def install(machine):
        for function, argc in signatures.items():
            module = "ntdll.dll" if function.startswith("rtl") or function.startswith("nt") else "advapi32.dll"
            machine.provide_export(callback, module = module, name = function, argc = argc)
        for imported in machine.imports:
            function = imported.name.lower()
            if _security_provider_module(imported.module) and function in signatures:
                machine.hook(callback, address = imported.address, argc = signatures[function])
    return emulator.plugin(install, name = "windows.security", state = state)

def _module_basename(name):
    normalized = name.replace("\\", "/").split("/")[-1].lower()
    return normalized if "." in normalized else normalized + ".dll"

_RESOURCE_SIGNATURES = {
    "enumresourcelanguagesa": 5,
    "enumresourcelanguagesw": 5,
    "enumresourcenamesa": 4,
    "enumresourcenamesw": 4,
    "enumresourcetypesa": 3,
    "enumresourcetypesw": 3,
    "findresourcea": 3,
    "findresourcew": 3,
    "findresourceexa": 4,
    "findresourceexw": 4,
    "freeresource": 1,
    "loadresource": 2,
    "lockresource": 1,
    "sizeofresource": 2,
}

def resource_plugin(file, module_files = {}, kernel = None):
    """Exposes immutable PE resources, selected by live module handles.

    `module_files` may be extended after plugin installation when the emulated
    loader maps a DLL lazily. Resource tables are parsed on first use so a
    LoadLibrary/FindResource sequence observes the same module state as NT
    without eagerly parsing every DLL available to the process.
    """
    resources_by_name = {"": windows.pe(file).resources}
    messages_by_name = {"": windows.pe(file).messages}
    for name, module_file in module_files.items():
        resources_by_name[_module_basename(name)] = windows.pe(module_file).resources
        messages_by_name[_module_basename(name)] = windows.pe(module_file).messages
    state = {"handles": {}, "loaded": {}, "modules": {}, "messages": {}, "identifiers": {}, "next_handle": 0x20000, "queries": []}

    def ensure_module_data(name):
        name = _module_basename(name)
        if name not in resources_by_name and name in module_files:
            module = windows.pe(module_files[name])
            resources_by_name[name] = module.resources
            messages_by_name[name] = module.messages
        return name

    def bind_module(machine, loaded):
        name = ensure_module_data(loaded.name)
        if loaded.primary:
            state["modules"][loaded.base] = resources_by_name[""]
            state["messages"][loaded.base] = messages_by_name[""]
        elif name in resources_by_name:
            state["modules"][loaded.base] = resources_by_name[name]
            state["messages"][loaded.base] = messages_by_name[name]
            address = machine.resolve_export(name, name = "COMResModuleInstance")
            if address:
                def module_instance(event, base = loaded.base):
                    return base
                machine.hook(module_instance, address = address, argc = 0)

    def bind_module_handle(machine, handle):
        if handle in state["modules"]:
            return
        for loaded in machine.modules:
            if loaded.base == handle:
                bind_module(machine, loaded)
                return

    def lookup(module, message_id, language):
        entries = state["messages"].get(module)
        if entries == None and module == 0:
            for name in ["kernel32.dll", "ntdll.dll"]:
                if name in messages_by_name:
                    entries = messages_by_name[name]
                    break
        if entries == None:
            return None
        selected = None
        for item in entries:
            if item.id != message_id:
                continue
            if selected == None or item.lang == "#" + str(language):
                selected = item.text
            if item.lang == "#" + str(language):
                break
        return selected

    def identifier(machine, value, wide):
        if value <= 0xffff:
            return "#" + str(value)
        return machine.read_cstring(value, encoding = "utf16le" if wide else "ascii")

    def callback_identifier(machine, value, wide):
        if value.startswith("#"):
            number = value[1:]
            if number and all([character >= "0" and character <= "9" for character in number]):
                return int(number)
        key = (value, wide)
        address = state["identifiers"].get(key)
        if address == None:
            address = machine.allocate(
                value = binary.encode(value, encoding = "utf16le" if wide else "ascii", nul = True),
                name = "PE resource identifier",
            )
            state["identifiers"][key] = address
        return address

    def module_resources(machine, instance):
        if instance:
            bind_module_handle(machine, instance)
        return state["modules"].get(instance, resources_by_name[""] if not instance else [])

    def invoke_enum(machine, callback_address, args):
        result = machine.invoke(callback_address, args = args)
        if result.reason != "return":
            fail("resource enumeration callback stopped with {}: {}".format(result.reason, result.detail))
        return result.value != 0

    def enumerate_types(machine, instance, callback_address, parameter, wide):
        seen = {}
        for item in module_resources(machine, instance):
            resource_type = item["type"]
            if resource_type in seen:
                continue
            seen[resource_type] = True
            if not invoke_enum(machine, callback_address, [instance, callback_identifier(machine, resource_type, wide), parameter]):
                return 0
        return 1

    def enumerate_names(machine, instance, type_value, callback_address, parameter, wide):
        resource_type = identifier(machine, type_value, wide)
        seen = {}
        for item in module_resources(machine, instance):
            if item["type"] != resource_type or item["name"] in seen:
                continue
            seen[item["name"]] = True
            if not invoke_enum(machine, callback_address, [instance, type_value, callback_identifier(machine, item["name"], wide), parameter]):
                return 0
        return 1

    def enumerate_languages(machine, instance, type_value, name_value, callback_address, parameter, wide):
        resource_type = identifier(machine, type_value, wide)
        resource_name = identifier(machine, name_value, wide)
        seen = {}
        for item in module_resources(machine, instance):
            if item["type"] != resource_type or item["name"] != resource_name:
                continue
            language = int(item["lang"][1:]) if item["lang"].startswith("#") else 0
            if language in seen:
                continue
            seen[language] = True
            if not invoke_enum(machine, callback_address, [instance, type_value, name_value, language, parameter]):
                return 0
        return 1

    def find(machine, instance, type_value, name_value, language, wide):
        type_name = identifier(machine, type_value, wide)
        item_name = identifier(machine, name_value, wide)
        selected = None
        resources = module_resources(machine, instance)
        for item in resources:
            if item["type"] == type_name and item["name"] == item_name:
                if selected == None or item["lang"] == "#" + str(language):
                    selected = item
                if item["lang"] == "#" + str(language):
                    break
        state["queries"].append({"module": instance, "type": type_name, "name": item_name, "language": language, "found": selected != None})
        if selected == None:
            return 0
        handle = state["next_handle"]
        state["next_handle"] = handle + 1
        state["handles"][handle] = {"data": selected["data"], "address": 0}
        return handle

    def load_resource_data(machine, item):
        if item["address"] == 0:
            mapped = binary.builder(capacity = len(item["data"]) + 1)
            mapped.append(item["data"])
            mapped.u8(0)
            item["address"] = machine.allocate(value = mapped.bytes(), name = "PE resource")
            state["loaded"][item["address"]] = item
        return item["address"]

    def callback(event):
        name = event.name.lower()
        args = event.args
        machine = event.machine
        wide = name.endswith("w")
        if name.startswith("enumresourcetypes"):
            return enumerate_types(machine, args[0], args[1], args[2], wide)
        if name.startswith("enumresourcenames"):
            return enumerate_names(machine, args[0], args[1], args[2], args[3], wide)
        if name.startswith("enumresourcelanguages"):
            return enumerate_languages(machine, args[0], args[1], args[2], args[3], args[4], wide)
        if name.startswith("findresourceex"):
            return find(machine, args[0], args[1], args[2], args[3], wide)
        if name.startswith("findresource"):
            # FindResource orders name before type, unlike FindResourceEx.
            return find(machine, args[0], args[2], args[1], 0, wide)
        if name == "loadresource":
            item = state["handles"].get(args[1])
            if item == None:
                return 0
            return load_resource_data(machine, item)
        if name == "lockresource":
            item = state["loaded"].get(args[0])
            if item != None:
                return args[0]
            item = state["handles"].get(args[0])
            if item == None:
                return 0
            return load_resource_data(machine, item)
        if name == "sizeofresource":
            item = state["handles"].get(args[1])
            return len(item["data"]) if item != None else 0
        if name == "freeresource":
            # Resources remain owned by their loaded module on NT5.
            return 1
        return 0

    signatures = _RESOURCE_SIGNATURES

    def install(machine):
        for loaded in machine.modules:
            bind_module(machine, loaded)
        for function, argc in signatures.items():
            machine.provide_export(callback, module = "kernel32.dll", name = function, argc = argc)
        for imported in machine.imports:
            function = imported.name.lower()
            if imported.module.lower() == "kernel32.dll" and function in signatures:
                machine.hook(callback, address = imported.address, argc = signatures[function])
        if kernel != None:
            kernel.state["message_lookup"] = lookup
    return emulator.plugin(install, name = "windows.resources", state = state)

def common_controls_plugin():
    """Models registration-time COMCTL32 strings and abstract image lists."""
    state = {"lists": {}, "next_list": 0x30000, "arrays": {}, "allocations": {}, "ui_language": 0x0409}

    def set_string_pointer(event, wide):
        target, source = event.args[0], event.args[1]
        if not source:
            event.machine.write_u32le(target, 0)
            return 1
        value = event.machine.read_cstring(source, encoding = "utf16le" if wide else "ascii")
        data = _encoded(value, wide)
        address = event.machine.allocate(size = len(data), value = data, name = "comctl32.string")
        event.machine.write_u32le(target, address)
        return 1

    def create_list(width, height, count = 0):
        handle = state["next_list"]
        state["next_list"] = handle + 1
        state["lists"][handle] = {"width": width, "height": height, "count": count, "background": 0xffffffff}
        return handle

    def sync_array(machine, handle):
        array = state["arrays"][handle]
        previous_data = array.get("data", 0)
        item_count = len(array["items"])
        data_size = max(1, item_count * array["size"])
        data = machine.allocate(size = data_size, name = "comctl32." + array["kind"] + "-data")
        if array["kind"] == "dsa":
            for index in range(item_count):
                machine.write(data + index * array["size"], array["items"][index])
        else:
            for index in range(item_count):
                machine.write_u32le(data + index * 4, array["items"][index])
        array["data"] = data
        if previous_data:
            machine.free(previous_data)
        machine.write_u32le(handle, len(array["items"]))
        machine.write_u32le(handle + 4, data)
        machine.write_u32le(handle + 8, len(array["items"]))
        machine.write_u32le(handle + 12, array["size"])
        machine.write_u32le(handle + 16, array["grow"])

    def refresh_array(machine, array):
        if array["kind"] != "dsa" or not array.get("data"):
            return
        array["items"] = [machine.read(array["data"] + index * array["size"], array["size"]) for index in range(len(array["items"]))]

    def create_array(machine, kind, size = 4, grow = 1):
        handle = machine.allocate(size = 20, name = "comctl32." + kind)
        state["arrays"][handle] = {"kind": kind, "size": size, "grow": grow, "items": [], "data": 0}
        sync_array(machine, handle)
        return handle

    def array_callback(event, function):
        args, machine = event.args, event.machine
        if function == 71:  # Alloc
            address = machine.allocate(size = max(1, args[0]), name = "comctl32.alloc")
            state["allocations"][address] = args[0]
            return address
        if function == 72:  # ReAlloc
            address = machine.allocate(size = max(1, args[1]), name = "comctl32.realloc")
            old_size = state["allocations"].get(args[0], 0)
            if old_size:
                machine.write(address, machine.read(args[0], min(old_size, args[1])))
            state["allocations"][address] = args[1]
            if args[0] in state["allocations"]:
                state["allocations"].pop(args[0])
                machine.free(args[0])
            return address
        if function == 73:  # Free
            if args[0] in state["allocations"]:
                state["allocations"].pop(args[0])
                machine.free(args[0])
            return None
        if function == 320:  # DSA_Create
            return create_array(machine, "dsa", args[0], args[1])
        if function in [328, 340]:  # DPA_Create, DPA_CreateEx
            return create_array(machine, "dpa", grow = args[0])
        array = state["arrays"].get(args[0]) if args else None
        if array == None:
            return 0
        items = array["items"]
        if function in [321, 329]:  # DSA_Destroy, DPA_Destroy
            state["arrays"][args[0]] = None
            return 1
        if function == 322:  # DSA_GetItem
            if args[1] >= len(items):
                return 0
            machine.write(args[2], machine.read(array["data"] + args[1] * array["size"], array["size"]))
            return 1
        if function == 323:  # DSA_GetItemPtr
            return array["data"] + args[1] * array["size"] if args[1] < len(items) else 0
        if function in [324, 325]:  # DSA_InsertItem, DSA_SetItem
            refresh_array(machine, array)
            items = array["items"]
            index = args[1]
            if function == 324 and index == 0x7fffffff:
                index = len(items)
            if index > len(items) or (function == 325 and index >= len(items)):
                return 0xffffffff if function == 324 else 0
            if function == 324:
                items.insert(index, machine.read(args[2], array["size"]))
                sync_array(machine, args[0])
                return index
            items[index] = machine.read(args[2], array["size"])
            sync_array(machine, args[0])
            return 1
        if function in [326, 336]:  # DSA_DeleteItem, DPA_DeletePtr
            if args[1] >= len(items):
                return 0
            refresh_array(machine, array)
            items = array["items"]
            value = items[args[1]]
            array["items"] = items[:args[1]] + items[args[1] + 1:]
            sync_array(machine, args[0])
            return value if function == 336 else 1
        if function in [327, 337]:  # DSA_DeleteAllItems, DPA_DeleteAllPtrs
            array["items"] = []
            sync_array(machine, args[0])
            return 1
        if function == 330:  # DPA_Grow
            return 1
        if function == 331:  # DPA_Clone
            clone = args[1] if args[1] in state["arrays"] else create_array(machine, "dpa")
            state["arrays"][clone]["items"] = list(items)
            sync_array(machine, clone)
            return clone
        if function == 332:  # DPA_GetPtr
            return items[args[1]] if args[1] < len(items) else 0
        if function == 333:  # DPA_GetPtrIndex
            return items.index(args[1]) if args[1] in items else 0xffffffff
        if function in [334, 335]:  # DPA_InsertPtr, DPA_SetPtr
            index = args[1]
            if function == 334 and index == 0x7fffffff:
                index = len(items)
            if index > len(items) or (function == 335 and index >= len(items)):
                return 0xffffffff if function == 334 else 0
            if function == 334:
                items.insert(index, args[2])
                sync_array(machine, args[0])
                return index
            items[index] = args[2]
            return 1
        return 0

    def callback(event, function):
        args = event.args
        if function == "initmuilanguage":
            state["ui_language"] = args[0] & 0xffff
            return None
        if type(function) == "int":
            return array_callback(event, function)
        if function == "imagelist_create":
            return create_list(args[0], args[1])
        if function in ["imagelist_loadimagea", "imagelist_loadimagew", "imagelist_read"]:
            return create_list(args[2], args[2], 1) if function.startswith("imagelist_load") else create_list(0, 0)
        image_list = state["lists"].get(args[0]) if args else None
        if function == "imagelist_destroy":
            if image_list == None:
                return 0
            state["lists"][args[0]] = None
            return 1
        if image_list == None:
            return 0
        if function == "imagelist_getimagecount":
            return image_list["count"]
        if function == "imagelist_geticonsize":
            event.machine.write_u32le(args[1], image_list["width"])
            event.machine.write_u32le(args[2], image_list["height"])
            return 1
        if function == "imagelist_seticonsize":
            image_list["width"], image_list["height"] = args[1], args[2]
            return 1
        if function == "imagelist_setbkcolor":
            previous = image_list["background"]
            image_list["background"] = args[1]
            return previous
        if function in ["imagelist_add", "imagelist_replaceicon"]:
            index = args[1] if function == "imagelist_replaceicon" else image_list["count"]
            if index == 0xffffffff:
                index = image_list["count"]
            if index > image_list["count"]:
                return 0xffffffff
            if index == image_list["count"]:
                image_list["count"] += 1
            return index
        if function == "imagelist_remove":
            if args[1] == 0xffffffff:
                image_list["count"] = 0
                return 1
            if args[1] >= image_list["count"]:
                return 0
            image_list["count"] -= 1
            return 1
        if function == "imagelist_geticon":
            return args[1] + 1 if args[1] < image_list["count"] else 0
        if function in ["imagelist_draw", "imagelist_drawex", "imagelist_setoverlayimage", "imagelist_write"]:
            return 1
        return 1

    def install(machine):
        signatures = {
            "imagelist_add": 3, "imagelist_begindrag": 4, "imagelist_create": 5,
            "imagelist_destroy": 1, "imagelist_dragenter": 3, "imagelist_dragleave": 1,
            "imagelist_dragmove": 2, "imagelist_dragshownolock": 1, "imagelist_draw": 6,
            "imagelist_drawex": 10, "imagelist_enddrag": 0, "imagelist_getdragimage": 2,
            "imagelist_geticon": 3, "imagelist_geticonsize": 3, "imagelist_getimagecount": 1,
            "imagelist_loadimagea": 7, "imagelist_loadimagew": 7, "imagelist_read": 1,
            "imagelist_remove": 2, "imagelist_replaceicon": 3, "imagelist_setbkcolor": 2,
            "imagelist_setdragcursorimage": 4, "imagelist_seticonsize": 3,
            "imagelist_setoverlayimage": 3, "imagelist_write": 2, "initcommoncontrolsex": 1,
            "initmuilanguage": 1,
        }
        ordinal_signatures = {
            17: 0,
            71: 1, 72: 2, 73: 1,
            320: 2, 321: 1, 322: 3, 323: 2, 324: 3, 325: 3, 326: 2, 327: 1,
            328: 1, 329: 1, 330: 2, 331: 2, 332: 2, 333: 2, 334: 3, 335: 3,
            336: 2, 337: 1, 340: 2,
        }
        for function, argc in signatures.items():
            def bound(event, function = function):
                return callback(event, function)
            machine.provide_export(bound, module = "comctl32.dll", name = function, argc = argc)
        for ordinal, argc in ordinal_signatures.items():
            def bound(event, ordinal = ordinal):
                return callback(event, ordinal)
            machine.provide_export(bound, module = "comctl32.dll", ordinal = ordinal, argc = argc)
        machine.provide_export(lambda event: set_string_pointer(event, False), module = "comctl32.dll", ordinal = 234, argc = 2)
        machine.provide_export(lambda event: set_string_pointer(event, True), module = "comctl32.dll", ordinal = 236, argc = 2)
        for imported in machine.imports:
            if imported.module.lower() != "comctl32.dll":
                continue
            if imported.ordinal == 234 or imported.name.lower() == "str_setptra":
                def ansi(event):
                    return set_string_pointer(event, False)
                machine.hook(ansi, address = imported.address, argc = 2)
            elif imported.ordinal == 236 or imported.name.lower() == "str_setptrw":
                def wide(event):
                    return set_string_pointer(event, True)
                machine.hook(wide, address = imported.address, argc = 2)
            elif imported.name.lower() in signatures:
                function = imported.name.lower()
                def bound(event, function = function):
                    return callback(event, function)
                machine.hook(bound, address = imported.address, argc = signatures[function])
            elif imported.ordinal in ordinal_signatures:
                function = imported.ordinal
                def bound(event, function = function):
                    return callback(event, function)
                machine.hook(bound, address = imported.address, argc = ordinal_signatures[function])
    return emulator.plugin(install, name = "windows.common-controls")

def shell_plugin(module_path, kernel = None):
    """Models the bounded SHLWAPI compatibility wrappers used by registrars."""
    normalized_module = module_path.replace("/", "\\")
    windows_directory = _module_windows_directory(normalized_module)
    state = {"counters": {}, "next_counter": 1, "messages": {}, "next_association": 1, "associations": {}}

    def invoke_interface(machine, interface, slot, arguments):
        vtable = machine.read_u32le(interface)
        target = machine.read_u32le(vtable + slot * 4)
        result = machine.invoke(target, args = [interface] + arguments)
        if result.reason != "return":
            fail("COM method %d stopped with %s: %s" % (slot, result.reason, result.detail))
        return result.value

    def association_object(machine):
        identifier = state["next_association"]
        state["next_association"] = identifier + 1
        association = {"references": 1, "name": ""}

        def query_interface(event):
            output = event.args[2]
            if not output:
                return 0x80004003  # E_POINTER
            event.machine.write_u32le(output, 0)
            requested = _guid_text(event.machine, event.args[1])
            if requested not in ["{00000000-0000-0000-C000-000000000046}", "{C46CA590-3C3F-11D2-BEE6-0000F805CA57}"]:
                return 0x80004002  # E_NOINTERFACE
            association["references"] += 1
            event.machine.write_u32le(output, event.args[0])
            return 0

        def add_ref(event):
            association["references"] += 1
            return association["references"]

        def release(event):
            association["references"] = max(0, association["references"] - 1)
            return association["references"]

        def initialize(event):
            association["name"] = event.machine.read_cstring(event.args[2], encoding = "utf16le") if event.args[2] else ""
            return 0

        def unavailable(event):
            # Setup asks this object only about associations which have not
            # yet been registered. Preserve the documented output contracts
            # while reporting that no association value is present.
            output = event.args[-1]
            if output:
                event.machine.write_u32le(output, 0)
            return 0x80004005  # E_FAIL

        methods = [
            ("QueryInterface", query_interface, 3), ("AddRef", add_ref, 1), ("Release", release, 1),
            ("Init", initialize, 5), ("GetString", unavailable, 6), ("GetKey", unavailable, 5),
            ("GetData", unavailable, 6), ("GetEnum", unavailable, 6),
        ]
        table = binary.builder(capacity = len(methods) * 4)
        for name, method, argc in methods:
            table.u32le(machine.provide_export(method, module = "trex.iqueryassociations", name = name + str(identifier), argc = argc))
        table_address = machine.allocate(value = table.bytes(), name = "IQueryAssociations.vtable")
        value = binary.builder(capacity = 4)
        value.u32le(table_address)
        interface = machine.allocate(value = value.bytes(), name = "IQueryAssociations")
        state["associations"][interface] = association
        return interface

    def callback(event, function):
        args = event.args
        machine = event.machine
        if function == 24:  # SHStringFromGUIDW
            value = _guid_text(machine, args[0])
            _write_string(machine, args[1], value, True, args[2])
            return len(value)
        if function == 23:  # SHStringFromGUIDA
            value = _guid_text(machine, args[0])
            _write_string(machine, args[1], value, False, args[2])
            return len(value)
        if function == 38:  # CharLowerWrapW
            if args[0] <= 0xffff:
                character = chr(args[0]).lower()
                return ord(character[0]) if character else args[0]
            value = machine.read_cstring(args[0], encoding = "utf16le")
            _write_string(machine, args[0], value.lower(), True)
            return args[0]
        if function == 52:  # CreateFileWrapW
            return 0xffffffff
        if function == 80:  # GetModuleFileNameWrapW
            return _write_string(machine, args[1], module_path, True, args[2])
        if function == 83:  # GetModuleHandleWrapW
            requested = machine.read_cstring(args[0], encoding = "utf16le") if args[0] else ""
            requested = requested.replace("\\", "/").split("/")[-1].lower()
            for loaded in machine.modules:
                if (not requested and loaded.primary) or loaded.name == requested:
                    return loaded.base
            return 0
        if function == 85:  # GetPrivateProfileIntWrapW
            return args[2]
        if function == 97:  # GetWindowsDirectoryWrapW
            return _write_string(machine, args[0], windows_directory, True, args[1])
        if function == 107:  # LoadStringWrapW
            target = machine.resolve_export("user32.dll", name = "LoadStringW")
            if not target:
                return 0
            result = machine.invoke(target, args = args)
            return result.value if result.reason == "return" else 0
        if function == 112:  # CopyFileWrapW
            return 0
        if function == 133:  # RegisterWindowMessageWrapW
            name = machine.read_cstring(args[0], encoding = "utf16le").lower()
            identifier = state["messages"].get(name)
            if identifier == None:
                identifier = 0xc000 + len(state["messages"])
                state["messages"][name] = identifier
            return identifier
        if function == 132:  # RegisterClipboardFormatWrapW
            target = machine.resolve_export("user32.dll", name = "RegisterClipboardFormatW")
            if not target:
                return 0
            result = machine.invoke(target, args = [args[0]])
            return result.value if result.reason == "return" else 0
        if function == "shcreateshellpalette":
            # The registration path only requires a valid shell-palette
            # handle; palette pixels are never observed by the registrar.
            return 1
        if function == "shgetinversecmap":
            # SHLWAPI caches an inverse lookup for the caller's 256-entry
            # RGBQUAD palette. The registrar only retains the returned map
            # identity, so the palette's process-stable address is the
            # appropriate in-memory identity for this setup session.
            return args[0] if args[0] and args[1] else 0
        if function == "strstria":
            value = machine.read_cstring(args[0], encoding = "ascii")
            substring = machine.read_cstring(args[1], encoding = "ascii")
            offset = value.lower().find(substring.lower())
            return 0 if offset < 0 else args[0] + offset
        if function == "wnsprintfa":
            format = machine.read_cstring(args[2], encoding = "ascii")
            value = _format_win32(machine, format, args[3:], False)[:max(0, args[1] - 1)]
            _write_string(machine, args[0], value, False)
            return len(value)
        if function == "strcatbuffa":
            left = machine.read_cstring(args[0], encoding = "ascii")
            right = machine.read_cstring(args[1], encoding = "ascii")
            _write_string(machine, args[0], (left + right)[:max(0, args[2] - 1)], False)
            return args[0]
        if function in ["shreggetboolusvaluea", "shreggetboolusvaluew"]:
            return args[3]
        if function == "assoccreate":
            # CLSID is passed by value on x86, occupying the first four
            # DWORD stack slots; REFIID and the output follow it.
            output = args[5]
            if not output:
                return 0x80004003  # E_POINTER
            machine.write_u32le(output, 0)
            if args[:4] != [0xa07034fd, 0x49546caa, 0xa2973fac, 0x8af91672]:
                return 0x80040111  # CLASS_E_CLASSNOTAVAILABLE
            if _guid_text(machine, args[4]) != "{C46CA590-3C3F-11D2-BEE6-0000F805CA57}":
                return 0x80004002  # E_NOINTERFACE
            machine.write_u32le(output, association_object(machine))
            return 0
        if function in ["shcreatestreamonfilea", "shcreatestreamonfilew"]:
            wide = function.endswith("w")
            output = args[2]
            if not output:
                return 0x80004003  # E_POINTER
            machine.write_u32le(output, 0)
            path = machine.read_cstring(args[0], encoding = "utf16le" if wide else "ascii").replace("/", "\\").lower()
            if kernel != None and path in kernel.state["paths"]:
                fail("SHCreateStreamOnFile requires a stream for existing setup path %s" % path)
            return 0x80070002  # HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)
        if type(function) == "int" and function >= 151 and function <= 158:  # StrCmp[N][I][C][A/W]
            wide = function in [152, 154, 156, 158]
            encoding = "utf16le" if wide else "ascii"
            left = machine.read_cstring(args[0], encoding = encoding)
            right = machine.read_cstring(args[1], encoding = encoding)
            if function <= 154:
                left, right = left[:args[2]], right[:args[2]]
            if function in [153, 154, 157, 158]:
                left, right = left.lower(), right.lower()
            return -1 if left < right else (1 if left > right else 0)
        if function == 193:  # SHGetCurColorRes
            return 32
        if function == 215:  # SHAnsiToUnicode
            value = machine.read_cstring(args[0], encoding = "ascii")[:max(0, args[2] - 1)]
            _write_string(machine, args[1], value, True, args[2])
            return len(value)
        if function == 217:  # SHUnicodeToAnsi
            value = machine.read_cstring(args[0], encoding = "utf16le")[:max(0, args[2] - 1)]
            _write_string(machine, args[1], value, False, args[2])
            return len(value)
        if function == 219:  # QISearch
            base, table, requested, output = args
            if not output:
                return 0x80004003  # E_POINTER
            def return_interface(offset):
                interface = base + offset
                machine.write_u32le(output, interface)
                vtable = machine.read_u32le(interface)
                add_ref = machine.read_u32le(vtable + 4)
                result = machine.invoke(add_ref, args = [interface])
                if result.reason != "return":
                    fail("QISearch AddRef stopped with %s: %s" % (result.reason, result.detail))
                return 0
            requested_iid = hex(machine.read(requested, 16))
            first_offset = 0
            for index in range(256):
                entry = table + index * 8
                iid = machine.read_u32le(entry)
                offset = machine.read_u32le(entry + 4)
                if index == 0:
                    first_offset = offset
                if not iid:
                    break
                if hex(machine.read(iid, 16)) == requested_iid:
                    return return_interface(offset)
            iunknown = "0000000000000000c000000000000046"
            if requested_iid == iunknown:
                return return_interface(first_offset)
            machine.write_u32le(output, 0)
            return 0x80004002  # E_NOINTERFACE
        if function == 236:  # SHPinDllOfCLSID
            if not args[0]:
                return 0
            # Loaded modules remain mapped for the lifetime of the isolated
            # registration process. Its primary image is therefore a stable
            # pin token for a known in-process server.
            for loaded in machine.modules:
                if loaded.primary:
                    return loaded.base
            return 1
        if function == 222:  # SHGlobalCounterCreate
            handle = state["next_counter"]
            state["next_counter"] = handle + 1
            state["counters"][handle] = args[0]
            return handle
        if function == 223:  # SHGlobalCounterGetValue
            return state["counters"].get(args[0], 0)
        if function == 224:  # SHGlobalCounterIncrement
            value = state["counters"].get(args[0], 0) + 1
            state["counters"][args[0]] = value
            return value
        if function == 266:  # SHRestrictionLookup
            return 0  # No policy values are present in the setup-time model.
        if function == 267:  # SHWeakQueryInterface
            outer, inner, requested, output = args
            machine.write_u32le(output, 0)
            if not outer or not inner:
                return 0x80004002  # E_NOINTERFACE
            result = invoke_interface(machine, inner, 0, [requested, output])
            if result & 0x80000000 == 0:
                invoke_interface(machine, outer, 2, [])
            return result
        if function == 276:  # WhichPlatform
            return 2  # PLATFORM_INTEGRATED
        if function in [269, 270]:  # GUIDFromStringA/W
            value = machine.read_cstring(args[0], encoding = "utf16le" if function == 270 else "ascii")
            raw = guid_bytes(value)
            if raw == None:
                return 0
            machine.write(args[1], raw)
            return 1
        if function == 294:  # SHGetIniStringW
            _write_string(machine, args[2], "", True, args[3])
            return 0
        if function == 295:  # SHSetIniStringW
            return 1
        if function == 296:  # CreateURLFileContentsW
            return 0
        if function == 308:  # IsBadStringPtrWrapW
            target = machine.resolve_export("kernel32.dll", name = "IsBadStringPtrW")
            if not target:
                return 1
            result = machine.invoke(target, args = args)
            return result.value if result.reason == "return" else 1
        if function == 309:  # LoadLibraryWrapW
            target = machine.resolve_export("kernel32.dll", name = "LoadLibraryW")
            if not target:
                return 0
            result = machine.invoke(target, args = [args[0]])
            return result.value if result.reason == "return" else 0
        if function == 312:  # GetPrivateProfileStringWrapW
            default = machine.read_cstring(args[2], encoding = "utf16le") if args[2] else ""
            return _write_string(machine, args[3], default, True, args[4])
        if function == 342:  # SHInterlockedCompareExchange
            previous = machine.read_u32le(args[0])
            if previous == args[2]:
                machine.write_u32le(args[0], args[1])
            return previous
        if function in [364, 365]:  # DoesStringRoundTripA/W
            wide_source = function == 365
            value = machine.read_cstring(args[0], encoding = "utf16le" if wide_source else "ascii")
            converted = []
            round_trips = True
            for index in range(len(value)):
                character = value[index:index + 1]
                if ord(character) <= 0x7f:
                    converted.append(character)
                else:
                    # The setup-time ACP is Windows-1252. Unknown characters
                    # are represented by the normal default character and do
                    # not survive an ANSI-to-Unicode round trip.
                    converted.append("?")
                    round_trips = False
            converted = "".join(converted)
            capacity = args[2]
            if capacity > 0 and args[1]:
                _write_string(machine, args[1], converted[:capacity - 1], False, capacity)
            if wide_source and len(converted) + 1 > capacity:
                round_trips = False
            return 1 if round_trips else 0
        if function == 356:  # CreateAllAccessSecurityAttributes
            # Windows 9x does not use NT security descriptors; the native
            # SHLWAPI contract returns NULL on this platform.
            if args[2]:
                machine.write_u32le(args[2], 0)
            return 0
        if function in [345, 346]:  # SHAnsiToAnsi / SHUnicodeToUnicode
            wide = function == 346
            value = machine.read_cstring(args[0], encoding = "utf16le" if wide else "ascii")[:max(0, args[2] - 1)]
            _write_string(machine, args[1], value, wide, args[2])
            return len(value)
        if function == 376:  # MLGetUILanguage
            return 0x0409
        if function in [377, 378]:  # MLLoadLibraryA/W
            requested = machine.read_cstring(args[0], encoding = "utf16le" if function == 378 else "ascii") if args[0] else ""
            requested = requested.replace("\\", "/").split("/")[-1].lower()
            for loaded in machine.modules:
                if loaded.name == requested:
                    return loaded.base
            # Multilingual resource loading falls back to the caller's base
            # module when no satellite library is installed.
            if args[1]:
                return args[1]
            for loaded in machine.modules:
                if loaded.primary:
                    return loaded.base
            return 0
        if function == 394:  # SHChangeNotifyWrap
            # Registration can announce its association changes, but there is
            # no Explorer process to receive the notification at image-build
            # time. The API has no return value.
            return None
        if function == 418:  # MLFreeLibrary
            return 1
        if function == 419:  # SHFlushSFCacheWrap
            # Registration updates shell-folder values before any Explorer
            # process exists, so there is no process-local cache to flush.
            return None
        if function == 424:  # SHGlobalCounterDecrement
            value = state["counters"].get(args[0], 0) - 1
            state["counters"][args[0]] = value
            return value
        if function == 437:  # IsOS
            return 1
        if function == 441:  # SHGetWebFolderFilePathW
            _write_string(machine, args[1], "", True, args[2])
            return 0x80070002  # HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)
        if function in [447, 448]:  # FixSlashesAndColonA/W
            wide = function == 448
            value = machine.read_cstring(args[0], encoding = "utf16le" if wide else "ascii")
            _write_string(machine, args[0], value.replace("/", "\\"), wide)
            return None
        if function in [455, 456]:  # PathIsValidCharA/W
            character = args[0] & (0xffff if function == 456 else 0xff)
            requested_class = args[1]
            if character > 0x7e:
                character_class = 0x100  # PATH_CHAR_CLASS_OTHER_VALID
            elif character < 0x20 or character in [ord("/"), ord("<"), ord(">"), ord("|")]:
                character_class = 0
            elif character == ord("?"):
                character_class = 0x001  # PATH_CHAR_CLASS_LETTER
            elif character == ord("*"):
                character_class = 0x002  # PATH_CHAR_CLASS_ASTERIX
            elif character == ord("."):
                character_class = 0x004  # PATH_CHAR_CLASS_DOT
            elif character == ord("\\"):
                character_class = 0x008  # PATH_CHAR_CLASS_BACKSLASH
            elif character == ord(":"):
                character_class = 0x010  # PATH_CHAR_CLASS_COLON
            elif character == ord(";"):
                character_class = 0x020  # PATH_CHAR_CLASS_SEMICOLON
            elif character == ord(","):
                character_class = 0x040  # PATH_CHAR_CLASS_COMMA
            elif character == ord(" "):
                character_class = 0x080  # PATH_CHAR_CLASS_SPACE
            elif character == ord("\""):
                character_class = 0x200  # PATH_CHAR_CLASS_DOUBLEQUOTE
            elif (character >= ord("A") and character <= ord("Z")) or (character >= ord("a") and character <= ord("z")):
                character_class = 0xffffffff  # PATH_CHAR_CLASS_ANY
            else:
                character_class = 0x100  # PATH_CHAR_CLASS_OTHER_VALID
            return requested_class & character_class
        if function in [459, 460]:  # SHExpandEnvironmentStringsA/W
            wide = function == 460
            value = machine.read_cstring(args[0], encoding = "utf16le" if wide else "ascii")
            value = expand_environment(value, {
                "windir": windows_directory,
                "systemroot": windows_directory,
                "programfiles": "C:\\Program Files",
                "commonprogramfiles": "C:\\Program Files\\Common Files",
            })
            required = len(value) + 1
            if args[1] and args[2] >= required:
                _write_string(machine, args[1], value, wide, args[2])
            return required
        if function == 461:  # SHGetAppCompatFlags
            return 0
        if function in ["urlcanonicalizea", "urlcanonicalizew"]:
            wide = function.endswith("w")
            if not args[0] or not args[2]:
                return 0x80070057  # E_INVALIDARG
            value = machine.read_cstring(args[0], encoding = "utf16le" if wide else "ascii")
            # SHLWAPI accepts DOS separators in file URLs but emits URL path
            # separators. Preserve the scheme/authority and remove dot path
            # components without inventing a host URL parser.
            value = value.replace("\\", "/")
            marker = value.find(":")
            prefix = value[:marker + 1] if marker >= 0 else ""
            rest = value[marker + 1:] if marker >= 0 else value
            leading = ""
            while rest.startswith("/"):
                leading += "/"
                rest = rest[1:]
            components = []
            for component in rest.split("/"):
                if component == ".":
                    continue
                if component == ".." and components and components[-1] != "..":
                    components.pop()
                elif component:
                    components.append(component)
            value = prefix + leading + "/".join(components)
            capacity = machine.read_u32le(args[2])
            required = len(value) + 1
            if not args[1] or capacity < required:
                machine.write_u32le(args[2], required)
                return 0x8007007a  # HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)
            _write_string(machine, args[1], value, wide, capacity)
            machine.write_u32le(args[2], len(value))
            return 0
        if function in ["pathremovefilespeca", "pathremovefilespecw"]:
            wide = function.endswith("w")
            value = machine.read_cstring(args[0], encoding = "utf16le" if wide else "ascii").replace("/", "\\")
            separator = value.rfind("\\")
            if separator < 0:
                return 0
            result = value[:separator]
            if separator == 2 and len(value) >= 3 and value[1] == ":":
                result = value[:3]
            _write_string(machine, args[0], result, wide)
            return 1
        if function in ["pathrenameextensiona", "pathrenameextensionw"]:
            wide = function.endswith("w")
            encoding = "utf16le" if wide else "ascii"
            value = machine.read_cstring(args[0], encoding = encoding)
            extension = machine.read_cstring(args[1], encoding = encoding)
            separator = max(value.rfind("\\"), value.rfind("/"))
            dot = value.rfind(".")
            if dot <= separator:
                dot = len(value)
            _write_string(machine, args[0], value[:dot] + extension, wide)
            return 1
        if function in ["pathremoveextensiona", "pathremoveextensionw"]:
            wide = function.endswith("w")
            encoding = "utf16le" if wide else "ascii"
            value = machine.read_cstring(args[0], encoding = encoding)
            separator = max(value.rfind("\\"), value.rfind("/"))
            dot = value.rfind(".")
            if dot > separator:
                _write_string(machine, args[0], value[:dot], wide)
            return None
        if function in ["pathparseiconlocationa", "pathparseiconlocationw"]:
            wide = function.endswith("w")
            encoding = "utf16le" if wide else "ascii"
            value = machine.read_cstring(args[0], encoding = encoding)
            separator = value.rfind(",")
            if separator < 0:
                return 0
            index_text = value[separator + 1:].strip()
            sign = -1 if index_text.startswith("-") else 1
            if index_text.startswith("-") or index_text.startswith("+"):
                index_text = index_text[1:]
            index = 0
            position = 0
            while position < len(index_text):
                character = index_text[position]
                if character < "0" or character > "9":
                    break
                index = index * 10 + ord(character) - ord("0")
                position += 1
            _write_string(machine, args[0], value[:separator].rstrip(), wide)
            return sign * index
        if function in ["pathquotespacesa", "pathquotespacesw"]:
            wide = function.endswith("w")
            encoding = "utf16le" if wide else "ascii"
            value = machine.read_cstring(args[0], encoding = encoding)
            if " " in value and not (value.startswith("\"") and value.endswith("\"")):
                _write_string(machine, args[0], "\"" + value + "\"", wide)
            return None
        if function in ["pathunquotespacesa", "pathunquotespacesw"]:
            wide = function.endswith("w")
            encoding = "utf16le" if wide else "ascii"
            value = machine.read_cstring(args[0], encoding = encoding)
            if len(value) >= 2 and value.startswith("\"") and value.endswith("\""):
                _write_string(machine, args[0], value[1:-1], wide)
            return None
        if function in ["pathstrippatha", "pathstrippathw"]:
            wide = function.endswith("w")
            encoding = "utf16le" if wide else "ascii"
            value = machine.read_cstring(args[0], encoding = encoding)
            separator = max(value.rfind("\\"), value.rfind("/"))
            _write_string(machine, args[0], value[separator + 1:], wide)
            return None
        if function in ["pathstriptoroota", "pathstriptorootw"]:
            wide = function.endswith("w")
            encoding = "utf16le" if wide else "ascii"
            value = machine.read_cstring(args[0], encoding = encoding).replace("/", "\\") if args[0] else ""
            root = ""
            if len(value) >= 2 and value[1] == ":":
                root = value[:2] + "\\"
            elif value.startswith("\\\\"):
                components = [part for part in value[2:].split("\\") if part]
                if len(components) >= 2:
                    root = "\\\\" + components[0] + "\\" + components[1]
            elif value.startswith("\\"):
                root = "\\"
            if not root:
                if args[0]:
                    _write_string(machine, args[0], "", wide)
                return 0
            _write_string(machine, args[0], root, wide)
            return 1
        if function in ["pathremoveargsa", "pathremoveargsw", "pathgetargsa", "pathgetargsw"]:
            wide = function.endswith("w")
            encoding = "utf16le" if wide else "ascii"
            value = machine.read_cstring(args[0], encoding = encoding)
            quoted = False
            separator = len(value)
            index = 0
            while index < len(value):
                character = value[index]
                if character == "\"":
                    quoted = not quoted
                elif not quoted and character in [" ", "\t"]:
                    separator = index
                    break
                index += 1
            if function.startswith("pathremoveargs"):
                _write_string(machine, args[0], value[:separator], wide)
                return None
            while separator < len(value) and value[separator] in [" ", "\t"]:
                separator += 1
            return args[0] + separator * (2 if wide else 1)
        if function in ["pathremoveblanksa", "pathremoveblanksw"]:
            wide = function.endswith("w")
            value = machine.read_cstring(args[0], encoding = "utf16le" if wide else "ascii")
            _write_string(machine, args[0], value.strip(), wide)
            return None
        if function in ["pathappenda", "pathappendw"]:
            wide = function.endswith("w")
            encoding = "utf16le" if wide else "ascii"
            base = machine.read_cstring(args[0], encoding = encoding).replace("/", "\\").rstrip("\\")
            suffix = machine.read_cstring(args[1], encoding = encoding).replace("/", "\\").lstrip("\\")
            _write_string(machine, args[0], base + ("\\" if base and suffix else "") + suffix, wide)
            return 1
        if function in ["pathcanonicalizea", "pathcanonicalizew"]:
            wide = function.endswith("w")
            encoding = "utf16le" if wide else "ascii"
            value = machine.read_cstring(args[1], encoding = encoding).replace("/", "\\")
            prefix = ""
            rest = value
            rooted = False
            if len(rest) >= 2 and rest[1] == ":":
                prefix = rest[:2]
                rest = rest[2:]
                rooted = rest.startswith("\\")
            elif rest.startswith("\\\\"):
                prefix = "\\\\"
                rest = rest[2:]
                rooted = True
            elif rest.startswith("\\"):
                prefix = "\\"
                rest = rest[1:]
                rooted = True
            components = []
            for component in rest.split("\\"):
                if not component or component == ".":
                    continue
                if component == "..":
                    if components and components[-1] != "..":
                        components.pop()
                    elif not rooted:
                        components.append(component)
                else:
                    components.append(component)
            separator = "\\" if rooted and prefix != "\\\\" else ""
            canonical = prefix + separator + "\\".join(components)
            if not canonical and rooted:
                canonical = "\\"
            _write_string(machine, args[0], canonical, wide)
            return 1
        if function in ["pathaddbackslasha", "pathaddbackslashw"]:
            wide = function.endswith("w")
            value = machine.read_cstring(args[0], encoding = "utf16le" if wide else "ascii").replace("/", "\\")
            if value and not value.endswith("\\"):
                value += "\\"
                _write_string(machine, args[0], value, wide)
            return args[0] + len(value) * (2 if wide else 1)
        if function in ["pathbuildroota", "pathbuildrootw"]:
            if not args[0] or args[1] < 0 or args[1] > 25:
                return 0
            _write_string(machine, args[0], chr(ord("A") + args[1]) + ":\\", function.endswith("w"))
            return args[0]
        if function in ["pathremovebackslasha", "pathremovebackslashw"]:
            wide = function.endswith("w")
            encoding = "utf16le" if wide else "ascii"
            value = machine.read_cstring(args[0], encoding = encoding).replace("/", "\\")
            is_drive_root = len(value) == 3 and value[1:] == ":\\"
            if len(value) > 1 and value.endswith("\\") and not is_drive_root:
                value = value[:-1]
                _write_string(machine, args[0], value, wide)
            return args[0] + len(value) * (2 if wide else 1)
        if function in ["pathcombinea", "pathcombinew"]:
            wide = function.endswith("w")
            encoding = "utf16le" if wide else "ascii"
            base = machine.read_cstring(args[1], encoding = encoding).replace("/", "\\").rstrip("\\") if args[1] else ""
            suffix = machine.read_cstring(args[2], encoding = encoding).replace("/", "\\").lstrip("\\") if args[2] else ""
            _write_string(machine, args[0], base + ("\\" if base and suffix else "") + suffix, wide)
            return args[0]
        if function in ["pathisfilespeca", "pathisfilespecw"]:
            wide = function.endswith("w")
            value = machine.read_cstring(args[0], encoding = "utf16le" if wide else "ascii")
            return 0 if "\\" in value or "/" in value or ":" in value else 1
        if function in ["pathgetdrivenumbera", "pathgetdrivenumberw"]:
            wide = function.endswith("w")
            value = machine.read_cstring(args[0], encoding = "utf16le" if wide else "ascii") if args[0] else ""
            if len(value) < 2 or value[1] != ":":
                return 0xffffffff
            letter = value[0:1].upper()
            if letter < "A" or letter > "Z":
                return 0xffffffff
            return ord(letter) - ord("A")
        if function in ["pathmakesystemfoldera", "pathmakesystemfolderw"]:
            return 1
        if function in ["pathmakeprettya", "pathmakeprettyw"]:
            wide = function.endswith("w")
            encoding = "utf16le" if wide else "ascii"
            value = machine.read_cstring(args[0], encoding = encoding)
            if value != value.upper():
                return 0
            pretty = value.lower()
            if len(pretty) >= 2 and pretty[1] == ":":
                pretty = pretty[0].upper() + pretty[1:]
            _write_string(machine, args[0], pretty, wide)
            return 1
        if function == "pathunexpandenvstringsw":
            value = machine.read_cstring(args[0], encoding = "utf16le")
            substitutions = [
                (windows_directory, "%SystemRoot%"),
                ("C:\\Program Files", "%ProgramFiles%"),
            ]
            for prefix, replacement in substitutions:
                if value.lower().startswith(prefix.lower()):
                    value = replacement + value[len(prefix):]
                    break
            if len(value) + 1 > args[2]:
                return 0
            _write_string(machine, args[1], value, True, args[2])
            return 1
        if function in ["pathfileexistsa", "pathfileexistsw"]:
            wide = function.endswith("w")
            path = machine.read_cstring(args[0], encoding = "utf16le" if wide else "ascii").replace("/", "\\").rstrip("\\").lower()
            return 1 if kernel != None and path in kernel.state["paths"] else 0
        if function in ["pathfindfilenamea", "pathfindfilenamew"]:
            wide = function.endswith("w")
            value = machine.read_cstring(args[0], encoding = "utf16le" if wide else "ascii")
            separator = max(value.rfind("\\"), value.rfind("/"))
            return args[0] + (separator + 1) * (2 if wide else 1)
        if function in ["pathfindextensiona", "pathfindextensionw"]:
            wide = function.endswith("w")
            value = machine.read_cstring(args[0], encoding = "utf16le" if wide else "ascii")
            separator = max(value.rfind("\\"), value.rfind("/"))
            extension = value.rfind(".")
            if extension <= separator:
                extension = len(value)
            return args[0] + extension * (2 if wide else 1)
        if function in ["pathisrelativea", "pathisrelativew"]:
            wide = function.endswith("w")
            value = machine.read_cstring(args[0], encoding = "utf16le" if wide else "ascii")
            absolute = value.startswith("\\") or (len(value) >= 2 and value[1] == ":")
            return 0 if absolute else 1
        if function in ["pathisunca", "pathisuncw"]:
            wide = function.endswith("w")
            value = machine.read_cstring(args[0], encoding = "utf16le" if wide else "ascii")
            return 1 if value.startswith("\\\\") else 0
        if function in ["pathisuncservera", "pathisuncserverw"]:
            wide = function.endswith("w")
            value = machine.read_cstring(args[0], encoding = "utf16le" if wide else "ascii").replace("/", "\\")
            components = [part for part in value[2:].split("\\") if part] if value.startswith("\\\\") else []
            return 1 if len(components) == 1 else 0
        if function in ["pathisuncserversharea", "pathisuncserversharew"]:
            wide = function.endswith("w")
            value = machine.read_cstring(args[0], encoding = "utf16le" if wide else "ascii").replace("/", "\\")
            components = [part for part in value[2:].split("\\") if part] if value.startswith("\\\\") else []
            return 1 if len(components) == 2 else 0
        if function in ["strcpynw", "strcpyw"]:
            value = machine.read_cstring(args[1], encoding = "utf16le")
            if function == "strcpynw":
                value = value[:max(0, args[2] - 1)]
            _write_string(machine, args[0], value, True)
            return args[0]
        if function in ["strdupa", "strdupw"]:
            if not args[0]:
                return 0
            wide = function.endswith("w")
            value = machine.read_cstring(args[0], encoding = "utf16le" if wide else "ascii")
            data = binary.encode(value, encoding = "utf16le" if wide else "ascii", nul = True)
            address = machine.allocate(value = data, name = function)
            if kernel != None:
                kernel.state["local_allocations"][address] = len(data)
            return address
        if function in ["strrettobufa", "strrettobufw"]:
            wide = function.endswith("w")
            if not args[0] or not args[2] or args[3] <= 0:
                return 0x80070057  # E_INVALIDARG
            kind = machine.read_u32le(args[0])
            if kind == 0:  # STRRET_WSTR
                pointer = machine.read_u32le(args[0] + 4)
                value = machine.read_cstring(pointer, encoding = "utf16le") if pointer else ""
            elif kind == 1:  # STRRET_OFFSET
                offset = machine.read_u32le(args[0] + 4)
                value = machine.read_cstring(args[1] + offset, encoding = "ascii") if args[1] else ""
            elif kind == 2:  # STRRET_CSTR
                value = machine.read_cstring(args[0] + 4, encoding = "ascii")
            else:
                return 0x80070057
            _write_string(machine, args[2], value[:args[3] - 1], wide, args[3])
            return 0
        if function in ["strcmpia", "strcmpnia", "strcmpiw", "strcmpniw"]:
            encoding = "utf16le" if function.endswith("w") else "ascii"
            left = machine.read_cstring(args[0], encoding = encoding)
            right = machine.read_cstring(args[1], encoding = encoding)
            if function in ["strcmpnia", "strcmpniw"]:
                left, right = left[:args[2]], right[:args[2]]
            left, right = left.lower(), right.lower()
            return -1 if left < right else (1 if left > right else 0)
        if function == "strchrw":
            value = machine.read_cstring(args[0], encoding = "utf16le")
            character = chr(args[1] & 0xffff)
            offset = value.find(character)
            return 0 if offset < 0 else args[0] + offset * 2
        if function == "strchra":
            value = machine.read_cstring(args[0], encoding = "ascii")
            offset = value.find(chr(args[1] & 0xff))
            return 0 if offset < 0 else args[0] + offset
        if function == "strrchra":
            value = machine.read_cstring(args[0], encoding = "ascii")
            limit = args[1] - args[0] if args[1] and args[1] >= args[0] else len(value)
            offset = value[:limit].rfind(chr(args[2] & 0xff))
            return 0 if offset < 0 else args[0] + offset
        if function == "strcspna":
            value = machine.read_cstring(args[0], encoding = "ascii")
            rejected = machine.read_cstring(args[1], encoding = "ascii")
            count = 0
            while count < len(value) and value[count] not in rejected:
                count += 1
            return count
        if function == "strstra":
            value = machine.read_cstring(args[0], encoding = "ascii")
            substring = machine.read_cstring(args[1], encoding = "ascii")
            offset = value.find(substring)
            return 0 if offset < 0 else args[0] + offset
        if function in ["strstrw", "strstriw"]:
            value = machine.read_cstring(args[0], encoding = "utf16le")
            substring = machine.read_cstring(args[1], encoding = "utf16le")
            offset = value.lower().find(substring.lower()) if function == "strstriw" else value.find(substring)
            return 0 if offset < 0 else args[0] + offset * 2
        if function == "strspnw":
            value = machine.read_cstring(args[0], encoding = "utf16le")
            accepted = machine.read_cstring(args[1], encoding = "utf16le")
            count = 0
            while count < len(value) and value[count] in accepted:
                count += 1
            return count
        if function in ["strtointa", "strtointw"]:
            value = machine.read_cstring(args[0], encoding = "utf16le" if function.endswith("w") else "ascii").strip()
            sign = -1 if value.startswith("-") else 1
            if value.startswith("-") or value.startswith("+"):
                value = value[1:]
            result = 0
            index = 0
            while index < len(value):
                character = value[index:index + 1]
                if character < "0" or character > "9":
                    break
                result = result * 10 + ord(character) - ord("0")
                index += 1
            return sign * result
        if function in ["strcatw", "strcatbuffw"]:
            left = machine.read_cstring(args[0], encoding = "utf16le")
            right = machine.read_cstring(args[1], encoding = "utf16le")
            value = left + right
            if function == "strcatbuffw":
                value = value[:max(0, args[2] - 1)]
            _write_string(machine, args[0], value, True)
            return args[0]
        if function == "wnsprintfw":
            format = machine.read_cstring(args[2], encoding = "utf16le")
            value = _format_win32(machine, format, args[3:], True)[:max(0, args[1] - 1)]
            _write_string(machine, args[0], value, True)
            return len(value)
        if function == "wvnsprintfw":
            format = machine.read_cstring(args[2], encoding = "utf16le")
            values = [machine.read_u32le(args[3] + index * 4) for index in range(16)]
            value = _format_win32(machine, format, values, True)[:max(0, args[1] - 1)]
            _write_string(machine, args[0], value, True)
            return len(value)
        if function == 413:  # SHGetMachineInfo
            # Registration only uses this private query to select optional
            # machine-specific tuning. Report no special machine flags.
            return 0
        if function == 169:  # SHReleaseThreadRef
            # Win98's implementation accepts an IUnknown **, releases the
            # referenced object, and clears the caller's slot. Registration
            # objects are modeled rather than executable COM instances here,
            # so clearing the observable reference completes the same
            # ownership transfer without calling through a synthetic vtable.
            if args[0]:
                machine.write_u32le(args[0], 0)
            return 0
        if function == 476:  # SHGetObjectCompatFlags
            # Setup's registry has no per-CLSID ShellCompatibility overrides.
            # The native API therefore reports an empty compatibility mask.
            return 0
        return 0

    def install(machine):
        machine.provide_export(lambda event: callback(event, "pathisunca"), module = "shlwapi.dll", name = "PathIsUNCA", argc = 1)
        machine.provide_export(lambda event: callback(event, "pathgetdrivenumbera"), module = "shlwapi.dll", name = "PathGetDriveNumberA", argc = 1)
        machine.provide_export(lambda event: callback(event, "pathgetdrivenumberw"), module = "shlwapi.dll", name = "PathGetDriveNumberW", argc = 1)
        machine.provide_export(lambda event: callback(event, "pathisrelativea"), module = "shlwapi.dll", name = "PathIsRelativeA", argc = 1)
        machine.provide_export(lambda event: callback(event, "pathstriptoroota"), module = "shlwapi.dll", name = "PathStripToRootA", argc = 1)
        machine.provide_export(lambda event: callback(event, "pathstriptorootw"), module = "shlwapi.dll", name = "PathStripToRootW", argc = 1)
        machine.provide_export(lambda event: callback(event, "shcreatestreamonfilea"), module = "shlwapi.dll", name = "SHCreateStreamOnFileA", argc = 3)
        machine.provide_export(lambda event: callback(event, "shcreatestreamonfilew"), module = "shlwapi.dll", name = "SHCreateStreamOnFileW", argc = 3)
        machine.provide_export(lambda event: callback(event, "strrettobufa"), module = "shlwapi.dll", name = "StrRetToBufA", argc = 4)
        machine.provide_export(lambda event: callback(event, "strrettobufw"), module = "shlwapi.dll", name = "StrRetToBufW", argc = 4)
        signatures = {23: 3, 24: 3, 38: 1, 52: 7, 80: 3, 83: 1, 85: 4, 97: 2, 107: 4, 112: 3, 132: 1, 133: 1, 151: 3, 152: 3, 153: 3, 154: 3, 155: 2, 156: 2, 157: 2, 158: 2, 169: 1, 193: 0, 215: 3, 217: 3, 219: 4, 222: 1, 223: 1, 224: 1, 236: 1, 241: 0, 266: 4, 267: 4, 269: 2, 270: 2, 276: 0, 294: 5, 295: 4, 296: 3, 308: 2, 309: 1, 312: 6, 342: 3, 345: 3, 346: 3, 356: 3, 364: 3, 365: 3, 376: 0, 377: 3, 378: 3, 394: 4, 413: 1, 418: 1, 419: 0, 424: 1, 437: 1, 441: 3, 447: 1, 448: 1, 455: 2, 456: 2, 459: 3, 460: 3, 461: 1, 476: 2}
        named_signatures = {"assoccreate": 3, "pathaddbackslasha": 1, "pathaddbackslashw": 1, "pathappenda": 2, "pathappendw": 2, "pathbuildroota": 2, "pathbuildrootw": 2, "pathcanonicalizea": 2, "pathcanonicalizew": 2, "pathcombinea": 3, "pathcombinew": 3, "pathfileexistsa": 1, "pathfileexistsw": 1, "pathfindextensiona": 1, "pathfindextensionw": 1, "pathfindfilenamea": 1, "pathfindfilenamew": 1, "pathgetargsa": 1, "pathgetargsw": 1, "pathisfilespeca": 1, "pathisfilespecw": 1, "pathisrelativew": 1, "pathisuncw": 1, "pathisuncservera": 1, "pathisuncserverw": 1, "pathisuncserversharea": 1, "pathisuncserversharew": 1, "pathmakeprettya": 1, "pathmakeprettyw": 1, "pathmakesystemfoldera": 1, "pathmakesystemfolderw": 1, "pathparseiconlocationa": 1, "pathparseiconlocationw": 1, "pathquotespacesa": 1, "pathquotespacesw": 1, "pathremoveargsa": 1, "pathremoveargsw": 1, "pathremovebackslasha": 1, "pathremovebackslashw": 1, "pathremoveblanksa": 1, "pathremoveblanksw": 1, "pathremoveextensiona": 1, "pathremoveextensionw": 1, "pathremovefilespeca": 1, "pathremovefilespecw": 1, "pathrenameextensiona": 2, "pathrenameextensionw": 2, "pathstrippatha": 1, "pathstrippathw": 1, "pathunexpandenvstringsw": 3, "pathunquotespacesa": 1, "pathunquotespacesw": 1, "shcreateshellpalette": 1, "shgetinversecmap": 2, "shreggetboolusvaluea": 4, "shreggetboolusvaluew": 4, "strcatbuffa": 3, "strcatbuffw": 3, "strcatw": 2, "strchra": 2, "strchrw": 2, "strcspna": 2, "strcmpia": 2, "strcmpiw": 2, "strcmpnia": 3, "strcmpniw": 3, "strcpynw": 3, "strcpyw": 2, "strdupa": 1, "strdupw": 1, "strrchra": 3, "strspnw": 2, "strstra": 2, "strstria": 2, "strstrw": 2, "strstriw": 2, "strtointa": 1, "strtointw": 1, "urlcanonicalizea": 4, "urlcanonicalizew": 4, "wnsprintfa": 16, "wnsprintfw": 16, "wvnsprintfw": 4}
        for ordinal, argc in signatures.items():
            def bound_ordinal(event, function = ordinal):
                return callback(event, function)
            machine.provide_export(bound_ordinal, module = "shlwapi.dll", ordinal = ordinal, argc = argc)
        for exported_name, argc in named_signatures.items():
            if exported_name == "assoccreate":
                argc = 6  # CLSID is a 16-byte by-value argument.
            def bound_named(event, function = exported_name):
                return callback(event, function)
            machine.provide_export(
                bound_named,
                module = "shlwapi.dll",
                name = exported_name,
                argc = argc,
                convention = "cdecl" if exported_name in ["wnsprintfa", "wnsprintfw"] else "stdcall",
            )
        for imported in machine.imports:
            if imported.module.lower() != "shlwapi.dll":
                continue
            function = imported.ordinal if imported.ordinal else imported.name.lower()
            argc = signatures.get(function) if type(function) == "int" else named_signatures.get(function)
            if argc != None:
                if function == "assoccreate":
                    argc = 6
                def bound(event, function = function):
                    return callback(event, function)
                machine.hook(bound, address = imported.address, argc = argc, convention = "cdecl" if function in ["wnsprintfa", "wnsprintfw"] else "stdcall")
    return emulator.plugin(install, name = "windows.shlwapi")

def gdi32_plugin():
    """Models registration-visible GDI stock objects without a host display."""
    state = {"next_palette": 0xda000001, "palettes": {}, "next_bitmap": 0xda100001, "bitmaps": {}}
    def callback(event):
        name = event.name.lower()
        if name == "getstockobject":
            # Stock-object identities are process-stable and owned by GDI.
            # A private pseudo-handle preserves those observable facts.
            return 0xd900 + (event.args[0] & 0xff)
        if name == "createsolidbrush":
            # A solid brush is completely described by its COLORREF. Keep a
            # stable nonzero pseudo-handle; callers only select or delete it.
            return 0xdb000000 | (event.args[0] & 0xffffff)
        if name == "createpalette":
            logical = event.args[0]
            if not logical:
                return 0
            version = event.machine.read_u16le(logical)
            count = event.machine.read_u16le(logical + 2)
            if version != 0x300 or count == 0:
                return 0
            handle = state["next_palette"]
            state["next_palette"] = handle + 1
            state["palettes"][handle] = event.machine.read(logical + 4, count * 4)
            return handle
        if name == "createdibitmap":
            handle = state["next_bitmap"]
            state["next_bitmap"] = handle + 1
            state["bitmaps"][handle] = {
                "header": event.args[1],
                "initialization": event.args[2],
                "bits": event.args[3],
                "information": event.args[4],
                "usage": event.args[5],
            }
            return handle
        if name == "getpaletteentries":
            count = event.args[2]
            if event.args[3]:
                entries = binary.builder(capacity = count * 4)
                for index in range(count):
                    intensity = ((event.args[1] + index) * 255 // max(1, count - 1)) & 0xff
                    entries.u8(intensity)
                    entries.u8(intensity)
                    entries.u8(intensity)
                    entries.u8(0)
                event.machine.write(event.args[3], entries.bytes())
            return count
        if name == "getdevicecaps":
            capabilities = {
                12: 32,  # BITSPIXEL
                14: 1,   # PLANES
                38: 0,   # RASTERCAPS: no palette-managed display
            }
            return capabilities.get(event.args[1], 0)
        if name in ["enumfontfamiliesa", "enumfontfamiliesw", "enumfontfamiliesexa", "enumfontfamiliesexw"]:
            # Registration/setup helpers use enumeration to choose UI fonts.
            # A headless semantic process has no installed display fonts; zero
            # is the native completed-enumeration result when none match.
            return 0
        if name == "deleteobject":
            state["palettes"].pop(event.args[0], None)
            state["bitmaps"].pop(event.args[0], None)
            return 1 if event.args[0] else 0
        return 0

    def install(machine):
        signatures = {"getstockobject": 1, "createsolidbrush": 1, "createpalette": 1, "createdibitmap": 6, "getpaletteentries": 4, "getdevicecaps": 2, "enumfontfamiliesa": 4, "enumfontfamiliesw": 4, "enumfontfamiliesexa": 5, "enumfontfamiliesexw": 5, "deleteobject": 1}
        for name, argc in signatures.items():
            machine.provide_export(callback, module = "gdi32.dll", name = name, argc = argc)
        for imported in machine.imports:
            name = imported.name.lower()
            if imported.module.lower() == "gdi32.dll" and name in signatures:
                machine.hook(callback, address = imported.address, argc = signatures[name])
    return emulator.plugin(install, name = "windows.gdi32", state = state)

def lz32_plugin(kernel):
    """Models the memory-backed LZ file-handle APIs used by setup helpers."""
    state = {"calls": []}
    def callback(event):
        name = event.name.lower()
        state["calls"].append({"api": name, "arguments": list(event.args)})
        if name == "lzopenfilea":
            style = event.args[2]
            create = style & 0x1000 != 0  # OF_CREATE
            opened = event.machine.invoke(
                event.machine.resolve_export("kernel32.dll", name = "CreateFileA"),
                args = [event.args[0], 0x40000000 if create else 0x80000000, 0, 0, 2 if create else 3, 0, 0],
            )
            return opened.value if opened.reason == "return" and opened.value != 0xffffffff else 0xffffffff
        if name == "lzcopy":
            source = kernel.state["handles"].get(event.args[0])
            target = kernel.state["handles"].get(event.args[1])
            if source == None or target == None or source.get("kind") != "file" or target.get("kind") != "file":
                return 0xffffffff
            source_state = source["value"]
            target_state = target["value"]
            data = kernel.state["file_data"](source_state["path"])[source_state["offset"]:]
            if data[:8] == b"SZDD\x88\xf0\x27\x33":
                encoded = binary.builder(capacity = len(data))
                encoded.append(data)
                data = archive.szdd(encoded.file()).bytes()
            if not kernel.state["write_file_data"](target_state["path"], target_state["offset"], data, machine = event.machine):
                return 0xffffffff
            source_state["offset"] += len(data)
            target_state["offset"] += len(data)
            return len(data)
        if name == "lzclose":
            return 0 if kernel.state["handles"].pop(event.args[0], None) != None else 0xffffffff
        return 0xffffffff

    def install(machine):
        signatures = {"LZOpenFileA": 3, "LZCopy": 2, "LZClose": 1}
        for name, argc in signatures.items():
            machine.provide_export(callback, module = "lz32.dll", name = name, argc = argc)
        folded = {name.lower(): argc for name, argc in signatures.items()}
        for imported in machine.imports:
            name = imported.name.lower()
            if imported.module.lower() == "lz32.dll" and name in folded:
                machine.hook(callback, address = imported.address, argc = folded[name])
    return emulator.plugin(install, name = "windows.lz32", state = state)

def shell32_plugin(module_path = "C:\\WINDOWS\\SYSTEM\\shell32.dll", environment = {}):
    """Models the process-local shell change-notification registrations."""
    state = {"next_registration": 1, "registrations": {}, "shell_settings": b"\x00" * 32, "desktop": 0, "desktop_references": 1, "pidls": {}}
    windows_directory = environment.get("windir", environment.get("WINDIR", _module_windows_directory(module_path))).replace("/", "\\").rstrip("\\")
    system_directory = windows_directory + "\\SYSTEM"
    profile = environment.get("USERPROFILE", windows_directory).replace("/", "\\").rstrip("\\")
    folder_paths = {
        0x00: profile + "\\Desktop",
        0x02: profile + "\\Start Menu\\Programs",
        0x05: environment.get("PERSONAL", "C:\\My Documents"),
        0x06: profile + "\\Favorites",
        0x07: profile + "\\Start Menu\\Programs\\StartUp",
        0x08: profile + "\\Recent",
        0x09: profile + "\\SendTo",
        0x0b: profile + "\\Start Menu",
        0x10: profile + "\\Desktop",
        0x14: windows_directory + "\\Fonts",
        0x15: windows_directory + "\\ShellNew",
        0x1a: profile + "\\Application Data",
        0x1b: profile + "\\PrintHood",
        0x1c: profile + "\\Application Data",
        0x1f: windows_directory + "\\All Users\\Favorites",
        0x23: windows_directory + "\\All Users\\Application Data",
        0x24: windows_directory,
        0x25: system_directory,
        0x26: "C:\\Program Files",
        0x27: profile + "\\My Pictures",
        0x2b: "C:\\Program Files\\Common Files",
    }

    def desktop_folder(machine):
        if state["desktop"]:
            return state["desktop"]

        def query_interface(event):
            if not event.args[2]:
                return 0x80004003
            event.machine.write_u32le(event.args[2], 0)
            requested = _guid_text(event.machine, event.args[1])
            if requested not in ["{00000000-0000-0000-C000-000000000046}", "{000214E6-0000-0000-C000-000000000046}"]:
                return 0x80004002
            state["desktop_references"] += 1
            event.machine.write_u32le(event.args[2], state["desktop"])
            return 0

        def add_ref(event):
            state["desktop_references"] += 1
            return state["desktop_references"]

        def release(event):
            state["desktop_references"] = max(0, state["desktop_references"] - 1)
            return state["desktop_references"]

        def parse_display_name(event):
            if not event.args[3] or not event.args[5]:
                return 0x80070057
            value = event.machine.read_cstring(event.args[3], encoding = "utf16le")
            payload = binary.encode(value, encoding = "utf16le", nul = True)
            item = binary.builder(capacity = len(payload) + 4)
            item.u16le(len(payload) + 2)
            item.append(payload)
            item.u16le(0)
            pidl = event.machine.allocate(value = item.bytes(), name = "ITEMIDLIST")
            state["pidls"][pidl] = value
            event.machine.write_u32le(event.args[5], pidl)
            if event.args[4]:
                event.machine.write_u32le(event.args[4], len(value))
            return 0

        def bind_to_object(event):
            if not event.args[4]:
                return 0x80004003
            event.machine.write_u32le(event.args[4], state["desktop"])
            state["desktop_references"] += 1
            return 0

        def get_attributes(event):
            return 0 if event.args[3] else 0x80070057

        def get_display_name(event):
            value = state["pidls"].get(event.args[1], "")
            if not event.args[3]:
                return 0x80004003
            text = event.machine.allocate(value = binary.encode(value, encoding = "utf16le", nul = True), name = "STRRET")
            event.machine.write_u32le(event.args[3], 0)  # STRRET_WSTR
            event.machine.write_u32le(event.args[3] + 4, text)
            return 0

        def unavailable(event):
            return 0x80004001  # E_NOTIMPL

        methods = [
            ("QueryInterface", query_interface, 3), ("AddRef", add_ref, 1), ("Release", release, 1),
            ("ParseDisplayName", parse_display_name, 7), ("EnumObjects", unavailable, 4),
            ("BindToObject", bind_to_object, 5), ("BindToStorage", unavailable, 5),
            ("CompareIDs", unavailable, 4), ("CreateViewObject", unavailable, 4),
            ("GetAttributesOf", get_attributes, 4), ("GetUIObjectOf", unavailable, 7),
            ("GetDisplayNameOf", get_display_name, 4), ("SetNameOf", unavailable, 6),
        ]
        table = binary.builder(capacity = len(methods) * 4)
        for name, method, argc in methods:
            table.u32le(machine.provide_export(method, module = "trex.ishellfolder", name = name, argc = argc))
        table_address = machine.allocate(value = table.bytes(), name = "IShellFolder.vtable")
        value = binary.builder(capacity = 4)
        value.u32le(table_address)
        state["desktop"] = machine.allocate(value = value.bytes(), name = "IShellFolder")
        return state["desktop"]

    def callback(event, function):
        if function == "dllgetversion":
            if not event.args[0] or event.machine.read_u32le(event.args[0]) < 20:
                return 0x80070057
            version = binary.builder(capacity = 20)
            version.u32le(20)
            version.u32le(4)
            version.u32le(72)
            version.u32le(3110)
            version.u32le(2)  # DLLVER_PLATFORM_WINDOWS
            event.machine.write(event.args[0], version.bytes())
            return 0
        if function in ["shgetfolderpatha", "shgetfolderpathw"]:
            if not event.args[4]:
                return 0x80070057  # E_INVALIDARG
            path = folder_paths.get(event.args[1] & 0xff)
            if path == None:
                event.machine.write(event.args[4], b"\x00\x00" if function.endswith("w") else b"\x00")
                return 0x80070002  # HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)
            _write_string(event.machine, event.args[4], path, function.endswith("w"), 260)
            return 0
        if function == "shgetdesktopfolder":
            if not event.args[0]:
                return 0x80004003
            event.machine.write_u32le(event.args[0], desktop_folder(event.machine))
            return 0
        if function == "shgetspecialfolderlocation":
            if not event.args[2]:
                return 0x80070057
            event.machine.write_u32le(event.args[2], 0)
            path = folder_paths.get(event.args[1] & 0xff)
            if path == None:
                return 0x80070002
            # ITEMIDLIST contents are opaque to callers. Preserve the resolved
            # path beside a correctly terminated empty list so a subsequent
            # SHGetPathFromIDList call observes the same shell folder.
            pidl = event.machine.allocate(value = b"\x00\x00", name = "special-folder.ITEMIDLIST")
            state["pidls"][pidl] = path
            event.machine.write_u32le(event.args[2], pidl)
            return 0
        if function in ["shgetpathfromidlista", "shgetpathfromidlistw"]:
            path = state["pidls"].get(event.args[0])
            if path == None or not event.args[1] or path.startswith("::{"):
                return 0
            _write_string(event.machine, event.args[1], path, function.endswith("w"), 260)
            return 1
        if function in [2, 640]:  # SHChangeNotifyRegister / NT variant
            handle = state["next_registration"]
            state["next_registration"] = handle + 1
            state["registrations"][handle] = {
                "window": event.args[0],
                "sources": event.args[1],
                "events": event.args[2],
                "message": event.args[3],
                "entries": event.args[4],
            }
            return handle
        if function in [4, 641]:  # SHChangeNotifyDeregister / NT variant
            return 1 if state["registrations"].pop(event.args[0], None) != None else 0
        if function == 155:  # ILFree
            if event.args[0] in state["pidls"]:
                state["pidls"].pop(event.args[0])
                event.machine.free(event.args[0])
            return None
        if function == 68:  # SHGetSetSettings
            if not event.args[0]:
                return None
            if event.args[2]:
                state["shell_settings"] = event.machine.read(event.args[0], 32)
            else:
                event.machine.write(event.args[0], state["shell_settings"])
            return None
        if function in [708, 709]:  # SHGetSetFolderCustomSettingsA/W
            # No desktop.ini exists in the freshly materialized profile, so a
            # read has no custom settings to return. Writes are not requested
            # by IE4UINIT's reconciliation phase.
            return 0x80004005  # E_FAIL
        return 0

    def install(machine):
        signatures = {2: 6, 4: 1, 68: 3, 155: 1, 640: 6, 641: 1, 708: 3, 709: 3}
        machine.provide_export(lambda event: callback(event, "dllgetversion"), module = "shell32.dll", name = "DllGetVersion", argc = 1)
        machine.provide_export(lambda event: callback(event, "shgetfolderpatha"), module = "shell32.dll", name = "SHGetFolderPathA", argc = 5)
        machine.provide_export(lambda event: callback(event, "shgetfolderpathw"), module = "shell32.dll", name = "SHGetFolderPathW", argc = 5)
        machine.provide_export(lambda event: callback(event, "shgetdesktopfolder"), module = "shell32.dll", name = "SHGetDesktopFolder", argc = 1)
        machine.provide_export(lambda event: callback(event, "shgetspecialfolderlocation"), module = "shell32.dll", name = "SHGetSpecialFolderLocation", argc = 3)
        machine.provide_export(lambda event: callback(event, "shgetpathfromidlista"), module = "shell32.dll", name = "SHGetPathFromIDListA", argc = 2)
        machine.provide_export(lambda event: callback(event, "shgetpathfromidlistw"), module = "shell32.dll", name = "SHGetPathFromIDListW", argc = 2)
        for ordinal, argc in signatures.items():
            def bound(event, function = ordinal):
                return callback(event, function)
            machine.provide_export(bound, module = "shell32.dll", ordinal = ordinal, argc = argc)
        for imported in machine.imports:
            if imported.module.lower() != "shell32.dll":
                continue
            if imported.name.lower() == "dllgetversion":
                machine.hook(lambda event: callback(event, "dllgetversion"), address = imported.address, argc = 1)
                continue
            if imported.name.lower() == "shgetspecialfolderlocation":
                machine.hook(lambda event: callback(event, "shgetspecialfolderlocation"), address = imported.address, argc = 3)
                continue
            if imported.ordinal not in signatures:
                continue
            function = imported.ordinal
            def bound(event, function = function):
                return callback(event, function)
            machine.hook(bound, address = imported.address, argc = signatures[function])
    return emulator.plugin(install, name = "windows.shell32", state = state)

def _number_text(value, kind, bits = 32):
    mask = (1 << bits) - 1
    value &= mask
    if kind in ["d", "i"]:
        return str(value - (1 << bits) if value & (1 << (bits - 1)) else value)
    if kind == "u":
        return str(value)
    text = hex(value)[2:]
    return text.upper() if kind == "X" else text

def _padded(text, width, left, zero):
    if len(text) >= width:
        return text
    padding = ("0" if zero else " ") * (width - len(text))
    return text + padding if left else padding + text

def _format_argument_word_count(format):
    """Returns the number of 32-bit variadic words consumed by a format."""
    count = 0
    offset = 0
    digits = "0123456789"
    while offset < len(format):
        if format[offset] != "%":
            offset += 1
            continue
        offset += 1
        if offset < len(format) and format[offset] == "%":
            offset += 1
            continue
        while offset < len(format) and format[offset] in "-+ 0#":
            offset += 1
        if offset < len(format) and format[offset] == "*":
            count += 1
            offset += 1
        else:
            while offset < len(format) and format[offset] in digits:
                offset += 1
        if offset < len(format) and format[offset] == ".":
            offset += 1
            if offset < len(format) and format[offset] == "*":
                count += 1
                offset += 1
            else:
                while offset < len(format) and format[offset] in digits:
                    offset += 1
        length = ""
        for candidate in ["I64", "I32", "ll"]:
            if format[offset:].startswith(candidate):
                length = candidate
                offset += len(candidate)
                break
        if length == "" and offset < len(format) and format[offset] in "hlwL":
            length = format[offset]
            offset += 1
        if offset >= len(format):
            break
        kind = format[offset]
        offset += 1
        if kind in "sSdiuxXcC":
            count += 2 if length in ["I64", "ll"] else 1
    return count

def _stack_format_arguments(event, fixed, format):
    return [
        event.machine.read_u32le(event.argument_address + (fixed + index) * 4)
        for index in range(_format_argument_word_count(format))
    ]

def _format_win32(machine, format, args, wide):
    output = ""
    offset = 0
    argument = 0
    digits = "0123456789"
    while offset < len(format):
        if format[offset] != "%":
            output += format[offset]
            offset += 1
            continue
        offset += 1
        if offset < len(format) and format[offset] == "%":
            output += "%"
            offset += 1
            continue

        left = False
        zero = False
        alternate = False
        while offset < len(format) and format[offset] in "-+ 0#":
            left = left or format[offset] == "-"
            zero = zero or format[offset] == "0"
            alternate = alternate or format[offset] == "#"
            offset += 1
        if offset < len(format) and format[offset] == "*":
            if argument >= len(args):
                break
            width = args[argument]
            argument += 1
            width = width - (1 << 32) if width & 0x80000000 else width
            if width < 0:
                left = True
                width = -width
            offset += 1
        else:
            width_text = ""
            while offset < len(format) and format[offset] in digits:
                width_text += format[offset]
                offset += 1
            width = int(width_text) if width_text else 0
        precision = -1
        if offset < len(format) and format[offset] == ".":
            offset += 1
            if offset < len(format) and format[offset] == "*":
                if argument >= len(args):
                    break
                precision = args[argument]
                argument += 1
                precision = precision - (1 << 32) if precision & 0x80000000 else precision
                if precision < 0:
                    precision = -1
                offset += 1
            else:
                precision_text = ""
                while offset < len(format) and format[offset] in digits:
                    precision_text += format[offset]
                    offset += 1
                precision = int(precision_text) if precision_text else 0
        length = ""
        for candidate in ["I64", "I32", "ll"]:
            if format[offset:].startswith(candidate):
                length = candidate
                offset += len(candidate)
                break
        if length == "" and offset < len(format) and format[offset] in "hlwL":
            length = format[offset]
            offset += 1
        if offset >= len(format) or argument >= len(args):
            break

        kind = format[offset]
        offset += 1
        value = args[argument]
        argument += 1
        bits = 64 if length in ["I64", "ll"] else 32
        if bits == 64:
            if argument >= len(args):
                break
            value |= args[argument] << 32
            argument += 1
        if kind in ["s", "S"]:
            if length in ["l", "w"]:
                string_wide = True
            elif length == "h":
                string_wide = False
            else:
                string_wide = wide if kind == "s" else not wide
            text = "(null)" if value == 0 else machine.read_cstring(value, encoding = "utf16le" if string_wide else "ascii")
            if precision >= 0:
                text = text[:precision]
        elif kind in ["d", "i", "u", "x", "X"]:
            text = _number_text(value, kind, bits = bits)
            if alternate and kind in ["x", "X"]:
                text = ("0X" if kind == "X" else "0x") + text
        elif kind in ["c", "C"]:
            if length in ["l", "w"]:
                character_wide = True
            elif length == "h":
                character_wide = False
            else:
                character_wide = wide if kind == "c" else not wide
            builder = binary.builder(capacity = 2 if character_wide else 1)
            if character_wide:
                builder.u16le(value & 0xffff)
            else:
                builder.u8(value & 0xff)
            text = binary.text(builder.bytes(), encoding = "utf16le" if character_wide else "ascii")
        else:
            text = "%" + kind
            argument -= 1
        output += _padded(text, width, left, zero and not left)
    return output

def user32_plugin(file, module_files = {}, kernel = None):
    """Models resources, bounded formatting, and a deterministic message queue.

    String-table resources follow the live loader state. `module_files` may be
    extended after installation when LoadLibrary maps a DLL lazily.
    """
    def resource_tables(module_file):
        tables = {}
        for resource in windows.pe(module_file).resources:
            if resource["type"] == "#6" and resource["name"].startswith("#"):
                tables[int(resource["name"][1:])] = resource["data"]
        return tables

    tables_by_name = {"": resource_tables(file)}
    for name, module_file in module_files.items():
        tables_by_name[_module_basename(name)] = resource_tables(module_file)
    state = {"formats": {}, "next_format": 0xc000, "images": {}, "messages": [], "dialogs": [], "next_image": 0xd000, "menus": {}, "next_menu": 0xd800, "accelerators": {}, "next_accelerator": 0xdc00, "classes": {}, "next_atom": 1, "windows": {}, "next_window": 0xe000, "hooks": {}, "next_hook": 0xe800, "tables": {}, "cursor_position": [0, 0]}

    def ensure_module_tables(name):
        name = _module_basename(name)
        if name not in tables_by_name and name in module_files:
            tables_by_name[name] = resource_tables(module_files[name])
        return name

    def bind_module(machine, loaded):
        name = ensure_module_tables(loaded.name)
        if loaded.primary:
            state["tables"][loaded.base] = tables_by_name[""]
        elif name in tables_by_name:
            state["tables"][loaded.base] = tables_by_name[name]

    def bind_module_handle(machine, handle):
        if handle in state["tables"]:
            return
        for loaded in machine.modules:
            if loaded.base == handle:
                bind_module(machine, loaded)
                return

    def message_matches(message, window, minimum, maximum):
        if window not in [0, 0xffffffff] and message["window"] != window:
            return False
        if window == 0xffffffff and message["window"] != 0:
            return False
        return (minimum == 0 and maximum == 0) or message["message"] >= minimum and message["message"] <= maximum

    def write_message(machine, address, message):
        output = binary.builder(capacity = 28)
        for value in [message["window"], message["message"], message["wparam"], message["lparam"], message["time"], message["x"], message["y"]]:
            output.u32le(value & 0xffffffff)
        machine.write(address, output.bytes())

    def string_resource(machine, instance, identifier):
        if instance:
            bind_module_handle(machine, instance)
        tables = state["tables"].get(instance, tables_by_name[""] if not instance else {})
        data = tables.get(identifier // 16 + 1)
        if data == None:
            return ""
        cursor = binary.cursor(data)
        for slot in range(16):
            if cursor.remaining < 2:
                return ""
            size = cursor.u16le()
            raw = cursor.bytes(size * 2)
            if slot == identifier % 16:
                return binary.text(raw, encoding = "utf16le")
        return ""

    def read_rect(machine, address):
        cursor = binary.cursor(machine.read(address, 16))
        return [cursor.i32le(), cursor.i32le(), cursor.i32le(), cursor.i32le()]

    def write_rect(machine, address, rectangle):
        encoded = binary.builder(capacity = 16)
        for coordinate in rectangle:
            encoded.u32le(coordinate & 0xffffffff)
        machine.write(address, encoded.bytes())

    def rect_empty(rectangle):
        return rectangle[0] >= rectangle[2] or rectangle[1] >= rectangle[3]

    def new_window(class_name = 0, name = 0, style = 0, parent = 0, identifier = 0):
        handle = state["next_window"]
        state["next_window"] = handle + 1
        state["windows"][handle] = {
            "class": class_name,
            "name": name,
            "style": style,
            "parent": parent,
            "id": identifier,
            "text": "",
            "controls": {},
            "longs": {},
        }
        return handle

    def dialog_control(parent, identifier):
        window = state["windows"].get(parent)
        if window == None:
            return 0
        handle = window["controls"].get(identifier)
        if handle == None:
            handle = new_window(parent = parent, identifier = identifier)
            window["controls"][identifier] = handle
        return handle

    def new_menu(instance, template):
        handle = state["next_menu"]
        state["next_menu"] = handle + 1
        state["menus"][handle] = {"instance": instance, "template": template}
        return handle

    def registered_class(machine, value, wide):
        if value <= 0xffff:
            for record in state["classes"].values():
                if record["atom"] == value:
                    return record
            return None
        name = machine.read_cstring(value, encoding = "utf16le" if wide else "ascii")
        return state["classes"].get(name.lower())

    def callback(event):
        name = event.name.lower()
        wide = name.endswith("w")
        if name in ["registerclassa", "registerclassw", "registerclassexa", "registerclassexw"]:
            structure = event.args[0]
            name_offset = 44 if name.startswith("registerclassex") else 36
            procedure_offset = 8 if name.startswith("registerclassex") else 4
            class_address = event.machine.read_u32le(structure + name_offset) if structure else 0
            class_name = event.machine.read_cstring(class_address, encoding = "utf16le" if wide else "ascii") if class_address else ""
            record = state["classes"].get(class_name.lower())
            if record == None:
                atom = state["next_atom"]
                state["next_atom"] = atom + 1
                record = {"atom": atom, "procedure": event.machine.read_u32le(structure + procedure_offset) if structure else 0}
                state["classes"][class_name.lower()] = record
            return record["atom"]
        if name in ["unregisterclassa", "unregisterclassw"]:
            if event.args[0] > 0xffff:
                class_name = event.machine.read_cstring(event.args[0], encoding = "utf16le" if wide else "ascii")
                state["classes"].pop(class_name.lower(), None)
            return 1
        if name in ["getclassinfoa", "getclassinfow", "getclassinfoexa", "getclassinfoexw"]:
            class_address = event.args[1]
            output = event.args[2]
            if not class_address or not output:
                return 0
            class_name = event.machine.read_cstring(class_address, encoding = "utf16le" if wide else "ascii")
            record = state["classes"].get(class_name.lower())
            built_in = class_name.lower() in ["button", "combobox", "edit", "listbox", "mdiclient", "scrollbar", "static", "#32770"]
            if record == None and not built_in:
                return 0
            # USER owns both registered application classes and the built-in
            # control classes. DllInstall only inspects/copies their metadata;
            # it does not dispatch through the returned window procedure.
            size = 48 if name.startswith("getclassinfoex") else 40
            cb_size = event.machine.read_u32le(output) if size == 48 else 0
            event.machine.write(output, b"\x00" * size)
            if size == 48:
                event.machine.write_u32le(output, cb_size if cb_size else 48)
                event.machine.write_u32le(output + 44, class_address)
                event.machine.write_u32le(output + 8, record.get("procedure", 0) if record != None else 0)
            else:
                event.machine.write_u32le(output + 36, class_address)
                event.machine.write_u32le(output + 4, record.get("procedure", 0) if record != None else 0)
            event.machine.write_u32le(output + (32 if size == 48 else 28), 0xd80f)
            return 1
        if name in ["createwindowexa", "createwindowexw"]:
            handle = new_window(
                class_name = event.args[1],
                name = event.args[2],
                style = event.args[3],
                parent = event.args[8],
                identifier = event.args[9],
            )
            window = state["windows"][handle]
            if event.args[9] in state["menus"]:
                window["menu"] = event.args[9]
            record = registered_class(event.machine, event.args[1], wide)
            procedure = record.get("procedure", 0) if record != None else 0
            creation = binary.builder(capacity = 48)
            for value in [event.args[11], event.args[10], event.args[9], event.args[8], event.args[7], event.args[6], event.args[5], event.args[4], event.args[3], event.args[2], event.args[1], event.args[0]]:
                creation.u32le(value)
            creation_address = event.machine.allocate(value = creation.bytes(), name = "CREATESTRUCT")
            # MFC's AfxHookWindowCreate uses a thread-local WH_CBT hook to bind
            # the HWND to its CWnd before USER sends WM_NCCREATE. Merely
            # retaining SetWindowsHookEx registrations leaves the window proc
            # without that association and it dereferences an invalid object.
            cbt_create_record = binary.builder(capacity = 8)
            cbt_create_record.u32le(creation_address)
            cbt_create_record.u32le(0)
            cbt_create = event.machine.allocate(value = cbt_create_record.bytes(), name = "CBT_CREATEWND")
            for hook in list(state["hooks"].values()):
                if hook["kind"] == 5 and hook["procedure"]:
                    hooked = _invoke_target(event.machine, hook["procedure"], [3, handle, cbt_create])
                    window["cbt_reason"] = hooked.reason
                    window["cbt_detail"] = hooked.detail
                    if hooked.reason == "return" and hooked.value:
                        state["windows"].pop(handle, None)
                        return 0
            if procedure:
                created = _invoke_target(event.machine, procedure, [handle, 0x81, 0, creation_address])
                window["nccreate_reason"] = created.reason
                window["nccreate_detail"] = created.detail
                if created.reason == "return" and created.value:
                    initialized = _invoke_target(event.machine, procedure, [handle, 0x01, 0, creation_address])
                    window["create_reason"] = initialized.reason
                    window["create_detail"] = initialized.detail
            return handle
        if name in ["loadmenua", "loadmenuw"]:
            return new_menu(event.args[0], event.args[1])
        if name in ["loadmenuindirecta", "loadmenuindirectw"]:
            return new_menu(0, event.args[0])
        if name in ["loadacceleratorsa", "loadacceleratorsw"]:
            handle = state["next_accelerator"]
            state["next_accelerator"] = handle + 1
            state["accelerators"][handle] = {"instance": event.args[0], "table": event.args[1]}
            return handle
        if name in ["translateacceleratora", "translateacceleratorw"]:
            return 0
        if name == "destroymenu":
            return 1 if state["menus"].pop(event.args[0], None) != None else 0
        if name == "setmenu":
            window = state["windows"].get(event.args[0])
            if window == None or (event.args[1] and event.args[1] not in state["menus"]):
                return 0
            window["menu"] = event.args[1]
            return 1
        if name == "getmenu":
            window = state["windows"].get(event.args[0])
            return 0 if window == None else window.get("menu", 0)
        if name == "drawmenubar":
            return 1 if event.args[0] in state["windows"] else 0
        if name == "getactivewindow":
            # Registration-time execution has no host window manager. Return
            # the last process-created window when one exists.
            handles = state["windows"].keys()
            return handles[-1] if handles else 0
        if name == "destroywindow":
            state["windows"].pop(event.args[0], None)
            return 1
        if name == "iswindow":
            return 1 if event.args[0] in state["windows"] else 0
        if name == "messagebeep":
            return 1
        if name in ["messageboxa", "messageboxw"]:
            encoding = "utf16le" if wide else "ascii"
            state["dialogs"].append({
                "text": event.machine.read_cstring(event.args[1], encoding = encoding) if event.args[1] else "",
                "caption": event.machine.read_cstring(event.args[2], encoding = encoding) if event.args[2] else "",
                "flags": event.args[3],
            })
            return 1  # IDOK
        if name in ["dialogboxparama", "dialogboxparamw", "dialogboxindirectparama", "dialogboxindirectparamw"]:
            handle = new_window(parent = event.args[2])
            dialog = {
                "instance": event.args[0],
                "template": event.args[1],
                "parent": event.args[2],
                "procedure": event.args[3],
                "parameter": event.args[4],
                "window": handle,
                "controls": {},
                "result": 1,
            }
            state["dialogs"].append(dialog)
            state["windows"][handle]["dialog"] = dialog
            if event.args[3]:
                initialized = _invoke_target(event.machine, event.args[3], [handle, 0x110, 0, event.args[4]])
                dialog["initialization_reason"] = initialized.reason
                dialog["initialization_detail"] = initialized.detail
            return dialog["result"]
        if name in ["createdialogparama", "createdialogparamw", "createdialogindirectparama", "createdialogindirectparamw"]:
            handle = new_window(parent = event.args[2])
            dialog = {
                "instance": event.args[0],
                "template": event.args[1],
                "parent": event.args[2],
                "procedure": event.args[3],
                "parameter": event.args[4],
                "window": handle,
                "controls": {},
                "modeless": True,
                "result": 0,
            }
            state["dialogs"].append(dialog)
            state["windows"][handle]["dialog"] = dialog
            if event.args[3]:
                initialized = _invoke_target(event.machine, event.args[3], [handle, 0x110, 0, event.args[4]])
                dialog["initialization_reason"] = initialized.reason
                dialog["initialization_detail"] = initialized.detail
            return handle
        if name == "enddialog":
            window = state["windows"].get(event.args[0])
            if window != None and window.get("dialog") != None:
                window["dialog"]["result"] = event.args[1]
            return 1
        if name in ["getdlgitem", "getdlgitemint", "getdlgitemtexta", "getdlgitemtextw", "setdlgitemint", "setdlgitemtexta", "setdlgitemtextw"]:
            control = dialog_control(event.args[0], event.args[1])
            if name == "getdlgitem":
                return control
            window = state["windows"].get(control)
            if name.startswith("setdlgitemtext"):
                encoding = "utf16le" if wide else "ascii"
                window["text"] = event.machine.read_cstring(event.args[2], encoding = encoding) if event.args[2] else ""
                parent = state["windows"].get(event.args[0])
                if parent != None and parent.get("dialog") != None:
                    parent["dialog"]["controls"][event.args[1]] = window["text"]
                return 1
            if name == "setdlgitemint":
                window["text"] = str(event.args[2])
                parent = state["windows"].get(event.args[0])
                if parent != None and parent.get("dialog") != None:
                    parent["dialog"]["controls"][event.args[1]] = window["text"]
                return 1
            if name.startswith("getdlgitemtext"):
                capacity = event.args[3]
                value = window["text"][:max(0, capacity - 1)]
                _write_string(event.machine, event.args[2], value, wide)
                return len(value)
            value = window["text"]
            valid = bool(value)
            for index in range(len(value)):
                if value[index] not in "0123456789":
                    valid = False
            return int(value) if valid else 0
        if name in ["setwindowtexta", "setwindowtextw", "getwindowtexta", "getwindowtextw", "getwindowtextlengtha", "getwindowtextlengthw"]:
            window = state["windows"].get(event.args[0])
            if window == None:
                return 0
            if name.startswith("setwindowtext"):
                window["text"] = event.machine.read_cstring(event.args[1], encoding = "utf16le" if wide else "ascii") if event.args[1] else ""
                return 1
            if name.startswith("getwindowtextlength"):
                return len(window["text"])
            capacity = event.args[2]
            value = window["text"][:max(0, capacity - 1)]
            _write_string(event.machine, event.args[1], value, wide)
            return len(value)
        if name in ["getwindowlonga", "getwindowlongw", "setwindowlonga", "setwindowlongw"]:
            window = state["windows"].get(event.args[0])
            if window == None:
                return 0
            index = event.args[1]
            previous = window["longs"].get(index, 0)
            if name.startswith("setwindowlong"):
                window["longs"][index] = event.args[2]
            return previous
        if name in ["sendmessagea", "sendmessagew", "senddlgitemmessagea", "senddlgitemmessagew"]:
            if name.startswith("senddlgitemmessage"):
                window_handle = dialog_control(event.args[0], event.args[1])
                message = event.args[2]
                wparam = event.args[3]
                lparam = event.args[4]
            else:
                window_handle = event.args[0]
                message = event.args[1]
                wparam = event.args[2]
                lparam = event.args[3]
            window = state["windows"].get(window_handle)
            if window == None:
                return 0
            if message == 0x0c:  # WM_SETTEXT
                window["text"] = event.machine.read_cstring(lparam, encoding = "utf16le" if wide else "ascii") if lparam else ""
                return 1
            if message == 0x0d:  # WM_GETTEXT
                value = window["text"][:max(0, wparam - 1)]
                _write_string(event.machine, lparam, value, wide)
                return len(value)
            if message == 0x0e:  # WM_GETTEXTLENGTH
                return len(window["text"])
            return 0
        if name == "getdlgctrlid":
            window = state["windows"].get(event.args[0])
            return window["id"] if window != None else 0
        if name in ["getparent", "iswindowvisible", "bringwindowtotop", "setforegroundwindow", "setwindowpos"]:
            window = state["windows"].get(event.args[0])
            if name == "getparent":
                return window["parent"] if window != None else 0
            return 1 if window != None else 0
        if name in ["getclassnamea", "getclassnamew"]:
            window = state["windows"].get(event.args[0])
            if window == None or event.args[2] <= 0:
                return 0
            value = "#32770" if window.get("dialog") != None else "Control"
            value = value[:event.args[2] - 1]
            _write_string(event.machine, event.args[1], value, wide)
            return len(value)
        if name == "getdesktopwindow":
            desktop = state.get("desktop")
            if desktop == None:
                desktop = new_window(class_name = 0, name = 0)
                state["desktop"] = desktop
            return desktop
        if name in ["getwindowrect", "getclientrect"]:
            if event.args[0] not in state["windows"] or not event.args[1]:
                return 0
            write_rect(event.machine, event.args[1], [0, 0, 640, 480])
            return 1
        if name in ["enumchildwindows", "enumwindows"]:
            parent = event.args[0] if name == "enumchildwindows" else 0
            callback_address = event.args[1] if name == "enumchildwindows" else event.args[0]
            parameter = event.args[2] if name == "enumchildwindows" else event.args[1]
            for handle, window in state["windows"].items():
                if callback_address and (not parent or window["parent"] == parent):
                    result = _invoke_target(event.machine, callback_address, [handle, parameter])
                    if result.reason == "return" and result.value == 0:
                        break
            return 1
        if name in ["defwindowproca", "defwindowprocw"]:
            return 0
        if name == "showwindow":
            return 0
        if name == "updatewindow":
            return 1
        if name == "getsystemmenu":
            return event.args[0] if event.args[0] in state["windows"] else 0
        if name == "deletemenu":
            return 1
        if name in ["peekmessagea", "peekmessagew", "getmessagea", "getmessagew"]:
            if not event.args[0]:
                return 0
            selected = -1
            for index in range(len(state["messages"])):
                if selected < 0 and message_matches(state["messages"][index], event.args[1], event.args[2], event.args[3]):
                    selected = index
            if selected < 0:
                return 0
            message = state["messages"][selected]
            write_message(event.machine, event.args[0], message)
            if name.startswith("getmessage") or event.args[4] & 1:  # PM_REMOVE
                state["messages"].pop(selected)
            return 0 if message["message"] == 0x12 else 1  # WM_QUIT
        if name in ["postmessagea", "postmessagew", "postthreadmessagea", "postthreadmessagew"]:
            offset = 1 if name.startswith("postthread") else 0
            state["messages"].append({
                "thread": event.args[0] if offset else 0,
                "window": 0 if offset else event.args[0],
                "message": event.args[1],
                "wparam": event.args[2],
                "lparam": event.args[3],
                "time": 0,
                "x": 0,
                "y": 0,
            })
            return 1
        if name == "postquitmessage":
            state["messages"].append({"thread": 0, "window": 0, "message": 0x12, "wparam": event.args[0], "lparam": 0, "time": 0, "x": 0, "y": 0})
            return None
        if name in ["msgwaitformultipleobjects", "msgwaitformultipleobjectsex"]:
            count = event.args[0]
            handles = event.args[1]
            if name == "msgwaitformultipleobjects":
                wait_all = event.args[2] != 0
                timeout = event.args[3]
            else:
                timeout = event.args[2]
                wait_all = event.args[4] & 1 != 0  # MWMO_WAITALL
            numbers = [event.machine.read_u32le(handles + index * 4) for index in range(count)] if count else []
            if state["messages"] and not wait_all:
                if kernel != None and kernel.state["current_thread"] != None:
                    kernel.state["current_thread"].pop("wait", None)
                return count
            result = kernel.state["wait_for_multiple_objects"](event.machine, count, handles, wait_all) if kernel != None and count else 0x102
            if result != 0x102:
                if kernel.state["current_thread"] != None:
                    kernel.state["current_thread"].pop("wait", None)
                return result
            if state["messages"]:
                if kernel != None and kernel.state["current_thread"] != None:
                    kernel.state["current_thread"].pop("wait", None)
                return count
            if timeout:
                if kernel != None:
                    kernel.state["pump_threads"](event.machine)
                    result = kernel.state["wait_for_multiple_objects"](event.machine, count, handles, wait_all) if count else 0x102
                    if result != 0x102:
                        return result
                    if state["messages"]:
                        return count
                    kernel.state["suspend_wait"](event.machine, numbers, wait_all, timeout, "user32 message or handle wait")
                else:
                    event.machine.stop("wait", detail = "user32 message or handle wait")
            return 0x102
        if name in ["translatemessage", "dispatchmessagea", "dispatchmessagew"]:
            return 1 if name == "translatemessage" else 0
        if name in ["getshellwindow", "getwindow", "findwindowa", "findwindoww", "findwindowexa", "findwindowexw"]:
            # Registration runs before Explorer owns the shell desktop.
            return 0
        if name == "getsystemmetrics":
            metrics = {
                0: 1024, 1: 768,       # SM_CXSCREEN, SM_CYSCREEN
                2: 17, 3: 17,          # SM_CXVSCROLL, SM_CYHSCROLL
                4: 23, 5: 1, 6: 1,     # SM_CYCAPTION, SM_CXBORDER, SM_CYBORDER
                11: 32, 12: 32,        # SM_CXICON, SM_CYICON
                13: 32, 14: 32,        # SM_CXCURSOR, SM_CYCURSOR
                15: 19, 16: 1024, 17: 749,
                20: 1, 21: 1, 30: 17, 31: 17,
                32: 4, 33: 4, 49: 16, 50: 16,
                67: 0,                 # SM_CLEANBOOT
            }
            return metrics.get(event.args[0], 0)
        if name == "getcursorpos":
            if not event.args[0]:
                return 0
            point = binary.builder(capacity = 8)
            point.u32le(state["cursor_position"][0] & 0xffffffff)
            point.u32le(state["cursor_position"][1] & 0xffffffff)
            event.machine.write(event.args[0], point.bytes())
            return 1
        if name == "setcursorpos":
            horizontal = event.args[0] - (1 << 32) if event.args[0] & 0x80000000 else event.args[0]
            vertical = event.args[1] - (1 << 32) if event.args[1] & 0x80000000 else event.args[1]
            state["cursor_position"] = [horizontal, vertical]
            return 1
        if name in ["setwindowshookexa", "setwindowshookexw"]:
            handle = state["next_hook"]
            state["next_hook"] = handle + 1
            state["hooks"][handle] = {
                "kind": event.args[0],
                "procedure": event.args[1],
                "module": event.args[2],
                "thread": event.args[3],
            }
            return handle
        if name == "unhookwindowshookex":
            state["hooks"].pop(event.args[0], None)
            return 1
        if name == "callnexthookex":
            return 0
        if name == "getdc":
            return 0xda00
        if name == "releasedc":
            return 1
        if name == "getkeyboardlayoutlist":
            if event.args[0] and event.args[1]:
                event.machine.write_u32le(event.args[1], 0x04090409)
            return 1
        if name in ["monitorfromwindow", "monitorfromrect", "monitorfrompoint"]:
            return 1
        if name == "enumdisplaymonitors":
            if not event.args[2]:
                return 0
            rectangle = event.machine.allocate(
                size = 16,
                value = binary.u32le(0) + binary.u32le(0) + binary.u32le(1024) + binary.u32le(768),
                name = "user32.monitor-rectangle",
            )
            result = event.machine.invoke(event.args[2], args = [1, event.args[0], rectangle, event.args[3]])
            return result.value if result.reason == "return" else 0
        if name == "allowsetforegroundwindow":
            return 1
        if name == "getsyscolor":
            colors = {
                0: 0x000000, 1: 0x800000, 2: 0x800000, 3: 0x808080,
                4: 0xc0c0c0, 5: 0xffffff, 6: 0x000000, 7: 0x000000,
                8: 0x000000, 9: 0xffffff, 10: 0xc0c0c0, 11: 0xc0c0c0,
                12: 0x808080, 13: 0x800000, 14: 0xffffff, 15: 0xc0c0c0,
                16: 0x808080, 17: 0x808080, 18: 0x000000, 20: 0xffffff,
            }
            return colors.get(event.args[0], 0)
        if name == "getsyscolorbrush":
            # Model stock system brushes as stable, nonzero pseudo-handles.
            # Registration code only passes these handles back to USER/GDI.
            return 0xd800 + (event.args[0] & 0xff)
        if name in ["systemparametersinfoa", "systemparametersinfow"]:
            if event.args[0] == 0x30 and event.args[2]:  # SPI_GETWORKAREA
                work_area = binary.builder(capacity = 16)
                for coordinate in [0, 0, 1024, 749]:
                    work_area.u32le(coordinate)
                event.machine.write(event.args[2], work_area.bytes())
                return 1
            return 0
        if name == "setrect":
            write_rect(event.machine, event.args[0], event.args[1:5])
            return 1
        if name == "setrectempty":
            write_rect(event.machine, event.args[0], [0, 0, 0, 0])
            return 1
        if name == "copyrect":
            write_rect(event.machine, event.args[0], read_rect(event.machine, event.args[1]))
            return 1
        if name == "equalrect":
            return 1 if read_rect(event.machine, event.args[0]) == read_rect(event.machine, event.args[1]) else 0
        if name == "isrectempty":
            return 1 if rect_empty(read_rect(event.machine, event.args[0])) else 0
        if name == "ptinrect":
            rectangle = read_rect(event.machine, event.args[0])
            horizontal, vertical = event.args[1], event.args[2]
            if horizontal & 0x80000000:
                horizontal -= 1 << 32
            if vertical & 0x80000000:
                vertical -= 1 << 32
            return 1 if horizontal >= rectangle[0] and horizontal < rectangle[2] and vertical >= rectangle[1] and vertical < rectangle[3] else 0
        if name in ["offsetrect", "inflaterect"]:
            rectangle = read_rect(event.machine, event.args[0])
            horizontal, vertical = event.args[1], event.args[2]
            if horizontal & 0x80000000:
                horizontal -= 1 << 32
            if vertical & 0x80000000:
                vertical -= 1 << 32
            if name == "offsetrect":
                rectangle = [rectangle[0] + horizontal, rectangle[1] + vertical, rectangle[2] + horizontal, rectangle[3] + vertical]
            else:
                rectangle = [rectangle[0] - horizontal, rectangle[1] - vertical, rectangle[2] + horizontal, rectangle[3] + vertical]
            write_rect(event.machine, event.args[0], rectangle)
            return 1
        if name in ["intersectrect", "unionrect"]:
            left = read_rect(event.machine, event.args[1])
            right = read_rect(event.machine, event.args[2])
            if name == "intersectrect":
                output = [max(left[0], right[0]), max(left[1], right[1]), min(left[2], right[2]), min(left[3], right[3])]
                if rect_empty(output):
                    output = [0, 0, 0, 0]
            elif rect_empty(left):
                output = right
            elif rect_empty(right):
                output = left
            else:
                output = [min(left[0], right[0]), min(left[1], right[1]), max(left[2], right[2]), max(left[3], right[3])]
            write_rect(event.machine, event.args[0], output)
            return 0 if rect_empty(output) else 1
        if name in ["loadimagea", "loadimagew", "loadcursora", "loadcursorw", "loadicona", "loadiconw"]:
            handle = state["next_image"]
            state["next_image"] = handle + 1
            state["images"][handle] = {
                "instance": event.args[0],
                "name": event.args[1],
                "type": event.args[2] if name.startswith("loadimage") else (2 if name.startswith("loadcursor") else 1),
                "width": event.args[3] if name.startswith("loadimage") else 0,
                "height": event.args[4] if name.startswith("loadimage") else 0,
                "flags": event.args[5] if name.startswith("loadimage") else 0,
            }
            return handle
        if name in ["charlowera", "charlowerw", "charuppera", "charupperw"]:
            if event.args[0] <= 0xffff:
                character = chr(event.args[0])
                character = character.upper() if name.startswith("charupper") else character.lower()
                return ord(character[0]) if character else event.args[0]
            encoding = "utf16le" if wide else "ascii"
            value = event.machine.read_cstring(event.args[0], encoding = encoding)
            value = value.upper() if name.startswith("charupper") else value.lower()
            _write_string(event.machine, event.args[0], value, wide)
            return event.args[0]
        if name in ["charlowerbuffa", "charlowerbuffw", "charupperbuffa", "charupperbuffw"]:
            width = 2 if wide else 1
            size = event.args[1] * width
            raw = event.machine.read(event.args[0], size)
            value = binary.text(raw, encoding = "utf16le" if wide else "ascii")
            converted = value.upper() if name.startswith("charupper") else value.lower()
            encoded = binary.encode(converted, encoding = "utf16le" if wide else "ascii")
            if len(encoded) == size:
                event.machine.write(event.args[0], encoded)
            return event.args[1]
        if name in ["charnexta", "charnextw"]:
            if event.args[0] == 0:
                return 0
            width = 2 if wide else 1
            unit = binary.cursor(event.machine.read(event.args[0], width))
            value = unit.u16le() if wide else unit.u8()
            return event.args[0] + width if value else event.args[0]
        if name in ["charpreva", "charprevw"]:
            start, current = event.args
            if not start or current <= start:
                return start
            previous = current - (2 if wide else 1)
            if wide and previous - 2 >= start:
                low = event.machine.read_u16le(previous)
                high = event.machine.read_u16le(previous - 2)
                if low >= 0xdc00 and low <= 0xdfff and high >= 0xd800 and high <= 0xdbff:
                    previous -= 2
            return previous
        if name in ["chartooema", "chartooemw"]:
            source_wide = name.endswith("w")
            value = event.machine.read_cstring(event.args[0], encoding = "utf16le" if source_wide else "ascii")
            _write_string(event.machine, event.args[1], value, False)
            return 1
        if name in ["chartooembuffa", "chartooembuffw"]:
            source_wide = name.endswith("w")
            width = 2 if source_wide else 1
            raw = event.machine.read(event.args[0], event.args[2] * width)
            value = binary.text(raw, encoding = "utf16le" if source_wide else "ascii")
            encoded = binary.encode(value, encoding = "ascii")
            event.machine.write(event.args[1], encoded[:event.args[2]])
            return 1
        if name == "destroyicon":
            state["images"][event.args[0]] = None
            return 1
        if name.startswith("loadstring"):
            capacity = event.args[3]
            if capacity <= 0:
                return 0
            value = string_resource(event.machine, event.args[0], event.args[1])[:capacity - 1]
            _write_string(event.machine, event.args[2], value, wide)
            return len(value)
        if name.startswith("registerclipboardformat") or name.startswith("registerwindowmessage"):
            value = event.machine.read_cstring(event.args[0], encoding = "utf16le" if wide else "ascii")
            identifier = state["formats"].get(value)
            if identifier == None:
                identifier = state["next_format"]
                state["next_format"] = identifier + 1
                state["formats"][value] = identifier
            return identifier
        if name in ["wvsprintfa", "wvsprintfw"]:
            format = event.machine.read_cstring(event.args[1], encoding = "utf16le" if wide else "ascii")
            values = [event.machine.read_u32le(event.args[2] + index * 4) for index in range(_format_argument_word_count(format))] if event.args[2] else []
            value = _format_win32(event.machine, format, values, wide)
            _write_string(event.machine, event.args[0], value, wide)
            return len(value)
        format = event.machine.read_cstring(event.args[1], encoding = "utf16le" if wide else "ascii")
        value = _format_win32(event.machine, format, _stack_format_arguments(event, 2, format), wide)
        _write_string(event.machine, event.args[0], value, wide)
        return len(value)

    def install(machine):
        for loaded in machine.modules:
            bind_module(machine, loaded)
        exported = {
            "LoadStringA": 4, "LoadStringW": 4,
            "RegisterClipboardFormatA": 1, "RegisterClipboardFormatW": 1,
            "RegisterWindowMessageA": 1, "RegisterWindowMessageW": 1,
            "GetSystemMetrics": 1, "GetSysColor": 1, "GetSysColorBrush": 1,
            "GetCursorPos": 1, "SetCursorPos": 2,
            "SetWindowsHookExA": 4, "SetWindowsHookExW": 4,
            "UnhookWindowsHookEx": 1, "CallNextHookEx": 4,
            "GetKeyboardLayoutList": 2,
            "GetDC": 1, "ReleaseDC": 2,
            "MonitorFromWindow": 2, "MonitorFromRect": 2, "MonitorFromPoint": 3,
            "EnumDisplayMonitors": 4,
            "AllowSetForegroundWindow": 1,
            "SystemParametersInfoA": 4, "SystemParametersInfoW": 4,
            "SetRect": 5, "SetRectEmpty": 1, "CopyRect": 2, "EqualRect": 2,
            "IsRectEmpty": 1, "PtInRect": 3, "OffsetRect": 3, "InflateRect": 3,
            "IntersectRect": 3, "UnionRect": 3,
            "LoadImageA": 6, "LoadImageW": 6,
            "LoadCursorA": 2, "LoadCursorW": 2,
            "LoadIconA": 2, "LoadIconW": 2,
            "RegisterClassA": 1, "RegisterClassW": 1,
            "RegisterClassExA": 1, "RegisterClassExW": 1,
            "GetClassInfoA": 3, "GetClassInfoW": 3,
            "GetClassInfoExA": 3, "GetClassInfoExW": 3,
            "UnregisterClassA": 2, "UnregisterClassW": 2,
            "CreateWindowExA": 12, "CreateWindowExW": 12,
            "DestroyWindow": 1,
            "IsWindow": 1,
            "GetActiveWindow": 0,
            "DefWindowProcA": 4, "DefWindowProcW": 4,
            "ShowWindow": 2, "UpdateWindow": 1,
            "MessageBeep": 1,
            "MessageBoxA": 4, "MessageBoxW": 4,
            "DialogBoxParamA": 5, "DialogBoxParamW": 5,
            "DialogBoxIndirectParamA": 5, "DialogBoxIndirectParamW": 5,
            "CreateDialogParamA": 5, "CreateDialogParamW": 5,
            "CreateDialogIndirectParamA": 5, "CreateDialogIndirectParamW": 5,
            "LoadMenuA": 2, "LoadMenuW": 2,
            "LoadMenuIndirectA": 1, "LoadMenuIndirectW": 1,
            "LoadAcceleratorsA": 2, "LoadAcceleratorsW": 2,
            "TranslateAcceleratorA": 3, "TranslateAcceleratorW": 3,
            "DestroyMenu": 1, "SetMenu": 2, "GetMenu": 1, "DrawMenuBar": 1,
            "EndDialog": 2,
            "GetDlgItem": 2, "GetDlgItemInt": 4,
            "GetDlgItemTextA": 4, "GetDlgItemTextW": 4,
            "SetDlgItemInt": 4, "SetDlgItemTextA": 3, "SetDlgItemTextW": 3,
            "SetWindowTextA": 2, "SetWindowTextW": 2,
            "GetWindowTextA": 3, "GetWindowTextW": 3,
            "GetWindowTextLengthA": 1, "GetWindowTextLengthW": 1,
            "GetWindowLongA": 2, "GetWindowLongW": 2,
            "SetWindowLongA": 3, "SetWindowLongW": 3,
            "SendMessageA": 4, "SendMessageW": 4,
            "SendDlgItemMessageA": 5, "SendDlgItemMessageW": 5,
            "GetDlgCtrlID": 1, "GetParent": 1,
            "IsWindowVisible": 1, "BringWindowToTop": 1,
            "SetForegroundWindow": 1, "SetWindowPos": 7,
            "GetClassNameA": 3, "GetClassNameW": 3,
            "GetDesktopWindow": 0,
            "GetWindowRect": 2, "GetClientRect": 2,
            "EnumChildWindows": 3, "EnumWindows": 2,
            "GetSystemMenu": 2, "DeleteMenu": 3,
            "CharLowerA": 1, "CharLowerW": 1,
            "CharUpperA": 1, "CharUpperW": 1,
            "CharLowerBuffA": 2, "CharLowerBuffW": 2,
            "CharUpperBuffA": 2, "CharUpperBuffW": 2,
            "CharNextA": 1, "CharNextW": 1,
            "CharPrevA": 2, "CharPrevW": 2, "DestroyIcon": 1,
            "CharToOemA": 2, "CharToOemW": 2,
            "CharToOemBuffA": 3, "CharToOemBuffW": 3,
            "GetShellWindow": 0, "GetWindow": 2,
            "FindWindowA": 2, "FindWindowW": 2,
            "FindWindowExA": 4, "FindWindowExW": 4,
            "PeekMessageA": 5, "PeekMessageW": 5,
            "GetMessageA": 4, "GetMessageW": 4,
            "PostMessageA": 4, "PostMessageW": 4,
            "PostThreadMessageA": 4, "PostThreadMessageW": 4,
            "PostQuitMessage": 1, "TranslateMessage": 1,
            "DispatchMessageA": 1, "DispatchMessageW": 1,
            "MsgWaitForMultipleObjects": 5, "MsgWaitForMultipleObjectsEx": 5,
        }
        for exported_name, argc in exported.items():
            machine.provide_export(callback, module = "user32.dll", name = exported_name, argc = argc)
        machine.provide_export(callback, module = "user32.dll", name = "wsprintfA", argc = 2, convention = "cdecl")
        machine.provide_export(callback, module = "user32.dll", name = "wsprintfW", argc = 2, convention = "cdecl")
        machine.provide_export(callback, module = "user32.dll", name = "wvsprintfA", argc = 3)
        machine.provide_export(callback, module = "user32.dll", name = "wvsprintfW", argc = 3)
        signatures = {name.lower(): argc for name, argc in exported.items()}
        for imported in machine.imports:
            name = imported.name.lower()
            if imported.module.lower() != "user32.dll":
                continue
            if name in signatures:
                machine.hook(callback, address = imported.address, argc = signatures[name])
            elif name in ["wsprintfa", "wsprintfw"]:
                machine.hook(callback, address = imported.address, argc = 2, convention = "cdecl")
            elif name in ["wvsprintfa", "wvsprintfw"]:
                machine.hook(callback, address = imported.address, argc = 3)
    return emulator.plugin(install, name = "windows.user32", state = state)
