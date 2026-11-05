"""Bounded, isolated KTM registry transactions for native installer calls."""
load("@stdlib//windows/emulation:abi.star", "object_attributes_layout", "counted_string_layout")

def registry_transactions_plugin(registry, kernel):
    """Model unnamed local transactions with synchronous commit and rollback.

    Registry operations through transacted handles use private overlays. Ordinary
    handles continue seeing committed state. Commit publishes only after checking
    that the parent overlay has not changed; concurrent writers are unsupported,
    never silently overwritten. Rollback and closing an active transaction discard
    its overlay. Named/distributed transactions, timeouts, notifications, alternate
    registry views, and non-close use of terminal transacted keys fail closed.
    """
    state={"transactions":{},"key_owners":{},"serial":0,"actions":[]}
    def record(api,handle,phase):
        if len(state["actions"])>=4096: fail("native transaction observation limit")
        item=dict(api=api,handle=handle,state=phase)
        state["actions"].append(item)
        registry.state["transaction_actions"].append(item)
    def close(handle):
        if handle in state["transactions"]:
            tx=state["transactions"][handle]
            if tx["closed"]: return False
            if tx["phase"]=="active": tx["phase"]="aborted"
            tx["closed"]=True
            record("close",handle,tx["phase"])
            return True
        owner=state["key_owners"].get(handle)
        if owner==None: return None
        child=state["transactions"][owner]["view"]
        return child._close_handle(handle) or False
    def duplicate(handle,desired_access,inherit,options):
        owner=state["key_owners"].get(handle)
        if owner==None: return None
        tx=state["transactions"][owner]
        if tx["phase"]!="active" or tx["closed"]:
            fail("duplication of a terminal transacted registry handle is not modeled")
        view=tx["view"]
        if view.state["next_handle"]>=tx["handle_limit"]: fail("native transaction key handle limit")
        outcome=view._duplicate_handle(handle,desired_access,inherit,options)
        if outcome==None: return (6,0)
        if outcome[0]==0: state["key_owners"][outcome[1]]=owner
        return outcome
    def dispatch_view(event,name,owner):
        tx=state["transactions"][owner]
        if name=="regclosekey": return 0 if close(event.args[0]) else 6
        if tx["phase"]!="active" or tx["closed"]:
            fail("non-close use of a terminal transacted registry handle is not modeled")
        if name=="regnotifychangekeyvalue" or not (name.startswith("reg") or name.startswith("nt")):
            fail("unsupported transacted registry operation: "+name)
        view=tx["view"]
        before=view.state["next_handle"]
        result=view._dispatch(event,name)
        after=view.state["next_handle"]
        if after>=tx["handle_limit"]: fail("native transaction key handle limit")
        for handle in range(before,after): state["key_owners"][handle]=owner
        return result
    def route(event,name):
        if not event.args: return None
        handle=event.args[0]
        if name in ["ntopenkey","ntopenkeyex","ntcreatekey","rtlpntopenkey","rtlpntcreatekey"]:
            attrs=event.args[2]
            layout=object_attributes_layout(event.machine.pointer_size)
            handle=event.machine.read_pointer(attrs+layout["RootDirectory"]) if attrs else 0
        owner=state["key_owners"].get(handle)
        return dispatch_view(event,name,owner) if owner!=None else None
    def callback(event):
        m,a,name=event.machine,event.args,event.name.lower()
        if name=="ntcreatetransaction":
            if not a[0]: return 0xc000000d
            access=a[1]&0xffffffff
            if a[2] or a[3] or a[4] or a[8] or a[5]&0xffffffff not in [0,1] or a[6]&0xffffffff or a[7]&0xffffffff:
                fail("only unnamed local transactions without timeout/isolation options are modeled")
            if access & ~0x1f003f: fail("unsupported native transaction access mask")
            description=""
            if a[9]:
                layout=counted_string_layout(m.pointer_size)
                length=m.read_u16le(a[9])
                if length>4096 or length%2: fail("invalid transaction description length")
                pointer=m.read_pointer(a[9]+layout["Buffer"])
                description=binary.text(m.read(pointer,length),encoding="utf16le") if length else ""
            serial=state["serial"]
            if serial>=128: fail("native transaction count limit")
            handle=0x30000000+serial
            first=0x10000000+serial*0x100000
            baseline=registry._transaction_data()
            view=registry._fork(first)
            state["transactions"][handle]=dict(view=view,baseline=baseline,phase="active",closed=False,access=access,description=description,handle_limit=first+0x100000)
            state["serial"]+=1
            m.write_pointer(a[0],handle)
            record(name,handle,"active")
            return 0
        if name in ["ntcommittransaction","ntrollbacktransaction"]:
            handle=a[0]
            tx=state["transactions"].get(handle)
            if tx==None or tx["closed"]:
                record(name,handle,"invalid-handle" if tx==None else "closed")
                return 0xc0000008
            if tx["phase"]!="active": return 0xc0190003
            if a[1]&0xff!=1: fail("asynchronous native transaction completion is not modeled")
            commit=name=="ntcommittransaction"
            if not tx["access"]&(8 if commit else 16): return 0xc0000022
            if commit: registry._commit_fork(tx["view"],tx["baseline"])
            tx["phase"]="committed" if commit else "aborted"
            record(name,handle,tx["phase"])
            return 0
        create=name=="regcreatekeytransactedw"
        owner=a[9] if create else a[5]
        extended=a[10] if create else a[6]
        if extended: fail("extended registry transaction parameters are not modeled")
        tx=state["transactions"].get(owner)
        if tx==None or tx["closed"]: return 6
        if tx["phase"]!="active": return 6701  # ERROR_TRANSACTION_NOT_ACTIVE
        # The native view is explicit. Do not silently accept WOW64 view flags.
        access=a[5] if create else a[3]
        if access&0x300: fail("alternate transacted registry views are not modeled")
        parent_owner=state["key_owners"].get(a[0])
        if parent_owner!=None and parent_owner!=owner: fail("cross-transaction root handle")
        if parent_owner==None and a[0] in registry.state["handles"]:
            tx["view"].state["handles"][a[0]]=registry.state["handles"][a[0]]
            tx["view"].state["handle_access"][a[0]]=registry.state["handle_access"].get(a[0])
        return dispatch_view(event,"regcreatekeyexw" if create else "regopenkeyexw",owner)
    def install(machine):
        if registry.state.get("native_transaction_router")!=None: fail("registry transaction router already installed")
        registry.state["native_transaction_router"]=route
        kernel.state.setdefault("handle_closers",[]).append(close)
        kernel.state.setdefault("handle_duplicators",[]).append(duplicate)
        native={"ntcreatetransaction":10,"ntcommittransaction":2,"ntrollbacktransaction":2}
        win32={"regcreatekeytransactedw":11,"regopenkeytransactedw":7}
        machine.provide_exports(callback,module="ntdll.dll",signatures=native)
        for provider in ["advapi32.dll","kernelbase.dll","api-ms-win-core-registry-l2-1-0.dll"]:
            machine.provide_exports(callback,module=provider,signatures=win32)
        for imported in machine.imports_named(list(native)+list(win32)):
            name=imported.name.lower()
            if name in native and imported.module.lower()=="ntdll.dll": machine.hook(callback,address=imported.address,argc=native[name])
            elif name in win32 and (imported.module.lower() in ["advapi32.dll","kernelbase.dll"] or imported.module.lower().startswith("api-ms-win-core-registry-")):
                machine.hook(callback,address=imported.address,argc=win32[name])
    return emulator.plugin(install,name="windows.registry-transactions",state=state)
