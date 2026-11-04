"""Read-only LSA identity boundary for the pinned offline servicing process.

Only SECURITY/Policy domain identity records are read; secrets, authentication,
account mutations and remote machines are outside this adapter. The explicit
query_access is an isolated process capability, not an inferred policy DACL or
a claim about a booted host. Native WCP owns SID cache interpretation.
"""

def read_servicing_policy(security):
    """Read the bounded servicing policy from explicit native inputs; reject unsupported source layout rather than synthesizing policy."""
    def record(name):
        key=security.find("/Policy/"+name)
        if key==None or list(key.value_records)!=["(default)"]:
            fail("missing or ambiguous servicing policy record: "+name)
        value=key.value_records["(default)"]
        if value.type!=0 or len(value.raw)>65544: fail("invalid servicing policy record: "+name)
        return value.raw
    def text(name):
        raw=record(name)
        if not raw: return ""
        if len(raw)<8: fail("short servicing policy string: "+name)
        size=binary.read_u16le(raw)
        capacity=binary.read_u16le(raw,2)
        offset=binary.read_u32le(raw,4)
        if offset!=8 or size%2 or capacity%2 or size>capacity or capacity>len(raw)-offset:
            fail("invalid servicing policy string bounds: "+name)
        result=binary.text(raw[offset:offset+size],encoding="utf16le")
        if chr(0) in result: fail("embedded NUL in servicing policy string")
        return result
    def domain_sid(name,empty=False):
        raw=record(name)
        if empty and not raw: return b""
        if len(raw)<8 or binary.read_u8(raw)!=1 or binary.read_u8(raw,1)>15 or len(raw)!=8+4*binary.read_u8(raw,1):
            fail("invalid servicing policy SID: "+name)
        return raw
    guid=record("PolDnDmG")
    if len(guid)!=16: fail("invalid servicing DNS domain GUID")
    return dict(account_name=text("PolAcDmN"),account_sid=domain_sid("PolAcDmS"),
        primary_name=text("PolPrDmN"),primary_sid=domain_sid("PolPrDmS",True),
        dns_name=text("PolDnDDN"),forest_name=text("PolDnTrN"),dns_guid=guid)

def servicing_lsa_plugin(security, query_access):
    """Serve classes 5 and 12 from explicit immutable target policy records.

    query_access must be an explicit bool. False denies POLICY_VIEW_LOCAL_INFORMATION;
    True permits that one right only. No MAXIMUM_ALLOWED or generic-access grant.
    Handles and result allocations are independent, owned and checkpointed.
    NTSTATUS failures preserve outputs and the Win32 thread last-error slot.
    """
    if type(query_access)!="bool": fail("servicing LSA requires explicit query authority")
    policy=read_servicing_policy(security)
    state=dict(handles={},buffers={},actions=[])
    def dispatch(e):
        m,a=e.machine,e.args
        name=e.name.lower()
        if len(state["actions"])>=4096: fail("servicing LSA action bound")
        state["actions"].append(name)
        p=m.pointer_size
        if name=="lsaopenpolicy":
            # Only local policy, zero reserved OBJECT_ATTRIBUTES members.
            if a[0]: fail("remote LSA policy is outside servicing authority")
            if not a[1] or not a[3]: return 0xc000000d
            size=48 if p==8 else 24
            offsets=[8,16,32,40] if p==8 else [4,8,16,20]
            if m.read_u32le(a[1])!=size or m.read_u32le(a[1]+(24 if p==8 else 12)) or any([m.read_pointer(a[1]+off) for off in offsets]):
                return 0xc000000d
            if a[2] & ~1 or (a[2] & 1 and not query_access): return 0xc0000022
            if len(state["handles"])>=128: fail("servicing LSA handle bound")
            handle=m.allocate(size=p,name="owned servicing LSA policy")
            state["handles"][handle]=a[2]
            m.write_pointer(a[3],handle)
            return 0
        if name=="lsaclose":
            if a[0] not in state["handles"]: return 0xc0000008
            state["handles"].pop(a[0])
            m.free(a[0])
            return 0
        if name=="lsafreememory":
            if not a[0]: return 0
            if a[0] not in state["buffers"]: return 0xc000000d
            state["buffers"].pop(a[0])
            m.free(a[0])
            return 0
        if name!="lsaqueryinformationpolicy": fail("unsupported servicing LSA call")
        if a[0] not in state["handles"]: return 0xc0000008
        if not state["handles"][a[0]] & 1: return 0xc0000022
        if not a[2]: return 0xc000000d
        kind=a[1]
        if kind not in [5,12]: fail("unsupported servicing LSA information class: "+str(kind))
        if len(state["buffers"])>=128: fail("servicing LSA allocation bound")
        unicode_size=16 if p==8 else 8
        strings=[policy["account_name"]] if kind==5 else [policy["primary_name"],policy["dns_name"],policy["forest_name"]]
        sid=policy["account_sid"] if kind==5 else policy["primary_sid"]
        encoded=[binary.encode(s,encoding="utf16le") for s in strings]
        sid_offset=unicode_size if kind==5 else 3*unicode_size+16
        fixed=sid_offset+p
        total=fixed+len(sid)
        for text in encoded:
            if len(text)>65532: fail("servicing LSA string exceeds UNICODE_STRING")
            total+=len(text)+2
        output=m.allocate(size=total,name="owned servicing LSA information")
        cursor=output+fixed
        if sid:
            m.write_pointer(output+sid_offset,cursor)
            m.write(cursor,sid)
            cursor+=len(sid)
        if kind==12: m.write(output+3*unicode_size,policy["dns_guid"])
        for i,text in enumerate(encoded):
            header=output+i*unicode_size
            m.write_u16le(header,len(text))
            m.write_u16le(header+2,len(text)+2)
            m.write_pointer(header+(8 if p==8 else 4),cursor)
            m.write(cursor,binary.concat([text,b"\x00\x00"]).bytes())
            cursor+=len(text)+2
        state["buffers"][output]=total
        m.write_pointer(a[2],output)
        return 0
    def install(m):
        for module in ["advapi32.dll","api-ms-win-security-lsapolicy-l1-1-0.dll","api-ms-win-security-lsapolicy-l1-1-1.dll"]:
            for name,count in {"LsaOpenPolicy":4,"LsaQueryInformationPolicy":3,"LsaFreeMemory":1,"LsaClose":1}.items():
                m.provide_export(dispatch,module=module,name=name,argc=count)
    return emulator.plugin(install,name="windows.servicing.lsa-policy",state=state)
