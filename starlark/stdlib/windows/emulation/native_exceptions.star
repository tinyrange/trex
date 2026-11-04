"""Execute AMD64 language-specific exception handling in explicit native DLLs.

This bridge marshals RaiseException and binds public runtime exports. Native
NTDLL walks PE unwind tables; native MSVCRT runs matching, cleanup, and catch
funclets. No private installer address or canned exception outcome is used.
"""

def native_exceptions_plugin(ntdll_module="native-ntdll.dll", crt_module="native-msvcrt.dll", exception_limit=256):
    """Bind explicitly loaded AMD64 runtime images; no implicit DLL loading.

    Install after the shared Windows process semantics. `finish(machine)` frees
    owned exception records only after the caller has completed all native calls
    and teardown; it closes this bridge to subsequent raises. `state.raises`
    records requested exceptions, not an assertion that each was handled.
    Hardware exceptions, dynamic function tables and nonlocal transfers across
    an embedding `machine.invoke` boundary are not supplied by this bridge.
    """
    if exception_limit < 1 or exception_limit > 4096:
        fail("native exception budget must be between 1 and 4096")
    state = dict(records=[], raises=[], finished=False)
    def transfer(target):
        def call(event):
            event.machine.transfer(target, stack_pointer=event.machine.get_register("rsp"))
        return call
    def install(machine):
        if machine.architecture != "amd64":
            fail("native exception bridge requires AMD64")
        def native(module, name):
            images = [item for item in machine.modules if item.name.lower() == module.lower() and item.image_size]
            if len(images) != 1:
                fail("native exception bridge requires an explicit PE image", module)
            address = machine.resolve_export(module, name=name)
            if address < images[0].base or address >= images[0].base + images[0].image_size:
                fail("exception runtime export is not native", module, name)
            return address
        # Query the modeled process, never native host memory or private loader
        # globals. NTDLL still parses the actual PE exception directory itself.
        query = machine.resolve_export("ntdll.dll", name="NtQueryVirtualMemory")
        if not query:
            fail("native exceptions require process image-query semantics")
        def image_query(event):
            result = event.machine.invoke(query, args=event.args)
            if result.reason != "return":
                fail("native exception image query failed", result.reason, result.detail)
            return result.value
        machine.hook(image_query, address=native(ntdll_module,"NtQueryVirtualMemory"), argc=6)
        raise_address = native(ntdll_module,"RtlRaiseException")
        def raise_exception(event):
            m = event.machine
            code,flags,count,values = event.args
            if state["finished"] or len(state["raises"]) >= exception_limit:
                fail("native exception bridge is closed or exhausted")
            if count > 15 or flags & ~1 or (count and not values):
                fail("unsupported RaiseException arguments")
            information = m.read(values,count*8) if count else b""
            record = m.allocate(size=152,name="native EXCEPTION_RECORD")
            m.write_u32le(record,code & 0xffffffff)
            m.write_u32le(record+4,flags)
            m.write_pointer(record+16,event.return_address)
            m.write_u32le(record+24,count)
            if count:
                m.write(record+32,information)
            state["records"].append(record)
            state["raises"].append(dict(code=code & 0xffffffff,flags=flags,address=event.return_address,information=information))
            # Tail entry retains the actual native caller's stack and unwind
            # metadata. Nested invoke would restore its context after a catch.
            m.set_register("rcx",record)
            m.transfer(raise_address,stack_pointer=m.get_register("rsp"))
        for module in ["kernel32.dll","kernelbase.dll","api-ms-win-core-errorhandling-l1-1-0.dll"]:
            machine.provide_export(raise_exception,module=module,name="RaiseException",argc=4)
        for name,argc in [("RtlRaiseException",1),("RtlUnwindEx",6),("RtlUnwind",4),("RtlVirtualUnwind",8),("RtlLookupFunctionEntry",3),("RtlCaptureContext",1),("RtlRestoreContext",2)]:
            machine.provide_export(transfer(native(ntdll_module,name)),module="ntdll.dll",name=name,argc=argc)
        for name,argc in [("??0exception@@QEAA@AEBQEBD@Z",2),("_CxxThrowException",2),("__CxxFrameHandler3",4),("??0exception@@QEAA@AEBQEBDH@Z",3),("?what@exception@@UEBAPEBDXZ",1),("??0exception@@QEAA@AEBV0@@Z",2),("??0exception@@QEAA@XZ",1),("??1exception@@UEAA@XZ",1)]:
            machine.provide_export(transfer(native(crt_module,name)),module="msvcrt.dll",name=name,argc=argc)
    def finish(machine):
        if state["finished"]:
            fail("native exception bridge already finished")
        for address in state["records"]:
            machine.free(address)
        state["records"] = []
        state["finished"] = True
    return emulator.plugin(install,name="windows.native-exceptions",state=state,attrs={"finish":finish})
