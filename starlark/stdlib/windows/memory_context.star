"""Context and content recovery from NT x86 memory, with explicit layouts.

These readers preserve per-artifact faults. Offsets, flag encodings, roots and
context seeds must come from the captured build, not a guessed Windows version.
"""

load("@stdlib//inspect:memory.star", "read_structure")

def _result(value, fault = None):
    return {"value": value, "complete": fault == None, "fault": fault}

def _bad(value, address, message, kind = "invalid-structure"):
    return _result(value, {"kind": kind, "address": address, "message": message})

def _probe(space, address, size):
    p = space.probe(address,size)
    if p.complete:
        return _result(p.data)
    f = p.fault
    return _result(p.data,{"kind":f.kind,"address":f.address,"physical_address":f.physical_address,"level":f.level,"message":f.message})

def _read(space, address, layout):
    if address < 0 or address + max([o+s for o,k,s in layout.values()]+[1]) > 1<<32:
        return _bad({},address,"invalid x86 structure range")
    return read_structure(space,address,layout)

def module_at(address, modules):
    """Returns every covering module and RVA; overlapping evidence is not hidden.

    modules is a list of dictionaries with base, size and optional name/path.
    An empty list means unattributed, not proof of suspicious executable memory.
    """
    return [{"module":m,"rva":address-m["base"]} for m in modules if m["base"]<=address and address<m["base"]+m["size"]]

def read_process_context(kernel, process_space, address, process_layout, peb_layout, parameter_layout):
    """Reads parent/create-time metadata and PEB process parameters separately.

    process_layout requires peb; other fields such as parent_pid/created are
    caller-defined. peb_layout requires parameters. parameter_layout requires
    flags and may contain unicode command_line, image_path and directory fields.
    FILETIME values remain raw 100 ns ticks. PIDs are not durable identities.
    Relative UNICODE_STRING buffers are resolved for unnormalized parameters.
    """
    process = _read(kernel,address,process_layout)
    result = {"process":process}
    if not process["complete"]:
        return _result(result,process["fault"])
    peb = process["value"]["peb"]
    if not peb:
        result["parameters"] = None
        return _result(result)
    p = _read(process_space,peb,peb_layout)
    if not p["complete"]:
        return _result(result,p["fault"])
    parameters = p["value"]["parameters"]
    if not parameters:
        return _bad(result,peb,"null process parameters")
    flags = _read(process_space,parameters,{"flags":parameter_layout["flags"]})
    if not flags["complete"]:
        return _result(result,flags["fault"])
    fields = {}
    for name,spec in parameter_layout.items():
        offset,kind,size = spec
        if kind == "unicode" and not flags["value"]["flags"] & 1:
            item = read_relative_unicode(process_space,parameters+offset,parameters)
            if item["complete"]:
                fields[name] = item["value"]
        else:
            item = _read(process_space,parameters,{name:spec})
            if item["complete"]:
                fields[name] = item["value"][name]
        if not item["complete"]:
            result["parameters"] = fields
            return _result(result,item["fault"])
    result["parameters"] = fields
    return _result(result)

def read_relative_unicode(space, address, pointer_base = 0):
    """Decodes a 32-bit UNICODE_STRING with an explicit buffer-pointer bias."""
    d = _read(space,address,{"length":(0,"uint",2),"capacity":(2,"uint",2),"pointer":(4,"uint",4)})
    if not d["complete"]:
        return _result(None,d["fault"])
    f = d["value"]
    if f["length"] & 1 or f["length"] > f["capacity"] or (f["length"] and not f["pointer"]):
        return _bad(None,address,"invalid UNICODE_STRING")
    pointer = pointer_base + f["pointer"]
    if pointer < 0 or pointer + f["length"] > 1<<32:
        return _bad(None,address,"Unicode pointer overflow")
    p = _probe(space,pointer,f["length"])
    if not p["complete"]:
        return _result(None,p["fault"])
    return _result(binary.text(p["value"],encoding="utf16le"))

def describe_vad(space, vad, flags, control_layout, file_layout):
    """Adds private/mapped, protection and backing-file evidence to one VAD.

    flags supplies private_bit, protection_shift, protection_mask, protections
    (numeric-code to descriptive value), and control_area_offset. Private VADs
    never read a long-VAD control-area field. control_layout requires file;
    file_layout describes FILE_OBJECT fields, conventionally type and name.
    Region permissions are allocation metadata, not CPU page-table permissions.
    """
    raw = vad["fields"]["flags"]
    private = bool(raw & (1<<flags["private_bit"]))
    protection = (raw>>flags["protection_shift"]) & flags["protection_mask"]
    result = {"region":vad,"private":private,"protection_code":protection,"protection":flags["protections"].get(protection),"backing_file":None}
    if private:
        return _result(result)
    control = _read(space,vad["address"],{"control":(flags["control_area_offset"],"uint",4)})
    if not control["complete"]:
        return _result(result,control["fault"])
    if not control["value"]["control"]:
        return _result(result)
    area = _read(space,control["value"]["control"],control_layout)
    if not area["complete"]:
        return _result(result,area["fault"])
    file = area["value"]["file"]
    if file:
        name = _read(space,file,file_layout)
        if not name["complete"]:
            return _result(result,name["fault"])
        if "type" in name["value"] and name["value"]["type"]!=5:
            return _bad(result,file,"backing pointer is not a FILE_OBJECT")
        result["backing_file"]={"address":file,"fields":name["value"]}
    return _result(result)

def walk_frames(space, frame_pointer, stack_limit, stack_base, modules = [], maximum = 128):
    """Walks a conventional x86 EBP chain within caller-proven stack bounds.

    Records saved return addresses, not arbitrary stack words. This is not an
    FPO/optimized-code unwinder. Null ends the chain; bounds, nonmonotonic links,
    missing pages or the frame limit stop it explicitly. Unmapped module names
    do not erase frames. A complete chain is not proof of a complete call stack.
    """
    if maximum<1 or maximum>4096 or stack_limit<0 or stack_limit>stack_base or stack_base>1<<32:
        fail("invalid stack bounds or limit")
    frames=[]
    fp=frame_pointer
    while fp:
        if len(frames)==maximum:
            return _bad(frames,fp,"frame bound reached","limit")
        if fp%4 or fp<stack_limit or fp+8>stack_base:
            return _bad(frames,fp,"frame pointer outside stack")
        frame=_read(space,fp,{"previous":(0,"uint",4),"return":(4,"uint",4)})
        if not frame["complete"]:
            return _result(frames,frame["fault"])
        previous=frame["value"]["previous"]
        if previous and previous<=fp:
            return _bad(frames,fp,"nonmonotonic frame chain")
        ret=frame["value"]["return"]
        frames.append({"frame_pointer":fp,"return_address":ret,"modules":module_at(ret,modules)})
        fp=previous
    return _result(frames)

def read_thread_context(kernel, process_space, address, layout, trap_layout, teb_layout, states, modules = [], maximum = 128):
    """Reads thread state/start attribution and a bounded trap-seeded EBP chain.

    Thread fields: state, start, trap, teb, stack_limit, stack_base; optional
    win32_start is also attributed. Trap fields: eip, ebp, cs, esp. TEB fields:
    stack_limit/stack_base. User-mode traps select process memory and TEB bounds;
    kernel traps select kernel memory and KTHREAD bounds. A saved trap context
    is not necessarily the running thread's current CPU state. Stack failure
    leaves readable thread metadata intact with its own result.
    """
    thread=_read(kernel,address,layout)
    if not thread["complete"]:
        return thread
    f=thread["value"]
    result={"fields":f,"state":states.get(f["state"]),"start_modules":module_at(f["start"],modules)}
    if "win32_start" in f:
        result["win32_start_modules"]=module_at(f["win32_start"],modules)
    if not f["trap"]:
        result["stack"]=_bad([],address,"no saved trap context","unavailable")
        return _result(result)
    trap=_read(kernel,f["trap"],trap_layout)
    result["trap"]=trap
    if not trap["complete"]:
        result["stack"]=_result([],trap["fault"])
        return _result(result)
    c=trap["value"]
    user=bool(c["cs"]&3)
    bounds=_read(process_space,f["teb"],teb_layout) if user and f["teb"] else _result(f)
    if user and not f["teb"]:
        bounds=_bad({},address,"user trap has no TEB")
    if not bounds["complete"]:
        result["stack"]=_result([],bounds["fault"])
        return _result(result)
    lower,upper=bounds["value"]["stack_limit"],bounds["value"]["stack_base"]
    if lower<0 or lower>upper or upper>1<<32 or c["esp"]<lower or c["esp"]>upper:
        result["stack"]=_bad([],f["trap"],"trap SP disagrees with stack bounds")
        return _result(result)
    result["stack"]=walk_frames(process_space if user else kernel,c["ebp"],lower,upper,modules,maximum)
    result["instruction_modules"]=module_at(c["eip"],modules)
    return _result(result)

def read_object_handles(space, handles, header_layout, type_layout, name_layout, body_offset, body_layouts = {}):
    """Reads all handle types with optional named, type-specific body fields.

    Header fields: type and name_offset (backward offset to optional name info).
    Type fields: name. Name-info layout normally includes unicode name and
    directory pointer. Names are object-manager components, not full paths.
    body_layouts maps exact type names to declarative fields; unknown types
    remain in the inventory. Each name/body has its own result and fault.
    Registry keys need their KCB path, not just an object-manager name. Named
    pipes are File objects; retain device/name evidence, not a guessed subtype.
    """
    if body_offset<0 or body_offset>4096:
        fail("invalid object body offset")
    entries=[]
    types={}
    for handle in handles["value"]:
        address=handle["object_header"]
        h=_read(space,address,header_layout)
        if not h["complete"]:
            return _result(entries,h["fault"])
        pointer=h["value"]["type"]
        if not pointer:
            return _bad(entries,address,"null object type")
        if pointer not in types:
            t=_read(space,pointer,type_layout)
            if not t["complete"]:
                return _result(entries,t["fault"])
            types[pointer]=t["value"]["name"]
        kind=types[pointer]
        offset=h["value"]["name_offset"]
        name=_read(space,address-offset,name_layout) if offset else _result(None)
        body=_read(space,address+body_offset,body_layouts[kind]) if kind in body_layouts else None
        entries.append({"handle":handle["handle"],"address":address+body_offset,"type":kind,"access":handle["access"],"name":name,"body":body})
    return _result(entries,handles["fault"])

def read_key_path(space, kcb, layout, name_layout, name_offset, maximum = 256):
    """Reads registry KCB ancestors and compressed/uncompressed name blocks.

    layout requires parent and name pointers. name_layout requires compressed
    and length; name_offset locates inline bytes. No registry values are read.
    Returned components are leaf-to-root so a partial path cannot look absolute.
    """
    if maximum<1 or maximum>4096 or name_offset<0 or name_offset>4096:
        fail("invalid registry path bounds")
    parts=[]
    seen={}
    while kcb:
        if kcb in seen:
            return _bad(parts,kcb,"KCB parent cycle")
        if len(parts)==maximum:
            return _bad(parts,kcb,"registry path bound reached","limit")
        seen[kcb]=True
        node=_read(space,kcb,layout)
        if not node["complete"]:
            return _result(parts,node["fault"])
        pointer=node["value"]["name"]
        if not pointer:
            return _bad(parts,kcb,"null key name block")
        name=_read(space,pointer,name_layout)
        if not name["complete"]:
            return _result(parts,name["fault"])
        length=name["value"]["length"]
        compressed=bool(name["value"]["compressed"])
        if length>65534 or (not compressed and length&1) or pointer+name_offset+length>1<<32:
            return _bad(parts,pointer,"invalid key name length")
        data=_probe(space,pointer+name_offset,length)
        if not data["complete"]:
            return _result(parts,data["fault"])
        # Compressed registry names zero-extend each byte to a UTF-16 code unit.
        raw=data["value"]
        if compressed:
            raw=bytes_concat([bytes_concat([raw[i:i+1],b"\x00"]) for i in range(len(raw))])
        parts.append(binary.text(raw,encoding="utf16le"))
        kcb=node["value"]["parent"]
    return _result(parts)

def read_object_path(space, body, body_offset, header_layout, name_layout, maximum = 128):
    """Walks named object-manager directories, returning leaf-to-root components.

    header_layout requires name_offset; name_layout requires directory and name.
    Directory pointers address object bodies. An unnamed object or missing
    ancestor returns a partial result, never an invented absolute path. Useful
    for events, sections and file device names such as Device/NamedPipe.
    """
    if body_offset<0 or body_offset>4096 or maximum<1 or maximum>4096:
        fail("invalid object path bounds")
    parts=[]
    seen={}
    while body:
        if body in seen or body<body_offset:
            return _bad(parts,body,"invalid/cyclic object directory")
        if len(seen)==maximum:
            return _bad(parts,body,"object path bound reached","limit")
        seen[body]=True
        header=body-body_offset
        item=_read(space,header,header_layout)
        if not item["complete"]:
            return _result(parts,item["fault"])
        offset=item["value"]["name_offset"]
        if not offset:
            return _bad(parts,body,"object has no name information","unnamed")
        name=_read(space,header-offset,name_layout)
        if not name["complete"]:
            return _result(parts,name["fault"])
        if name["value"]["name"]:
            parts.append(name["value"]["name"])
        body=name["value"]["directory"]
    return _result(parts)

def read_endpoints(space, table, buckets, layout, maximum = 16384):
    """Reads an explicitly rooted IPv4 endpoint hash table with singly linked buckets.

    Layout requires next, pid (uint), local_address (4 bytes), local_port
    (2 network-order bytes); optional remote fields use the same encodings.
    Protocol/state fields are retained raw. This is a table reader, not a pool
    signature scan or automatic tcpip.sys version detector. Zero buckets with
    a null root describe an uninitialized table, not proof of no network use.
    """
    if buckets<0 or buckets>65536 or maximum<1 or maximum>65536:
        fail("invalid endpoint bounds")
    if not table:
        return _bad([],0,"endpoint table is not initialized","unavailable")
    entries=[]
    seen={}
    for bucket in range(buckets):
        head=_read(space,table+bucket*4,{"head":(0,"uint",4)})
        if not head["complete"]:
            return _result(entries,head["fault"])
        node=head["value"]["head"]
        while node:
            if node%4 or node in seen:
                return _bad(entries,node,"invalid/repeated endpoint pointer")
            if len(entries)==maximum:
                return _bad(entries,node,"endpoint bound reached","limit")
            seen[node]=True
            fields=_read(space,node,layout)
            if not fields["complete"]:
                return _result(entries,fields["fault"])
            f=fields["value"]
            entry={"address":node,"fields":f,"pid":f["pid"]}
            for side in ["local","remote"]:
                if side+"_address" in f:
                    raw=f[side+"_address"]
                    port=f[side+"_port"]
                    if len(raw)!=4 or len(port)!=2:
                        fail("endpoint address/port widths must be 4/2")
                    entry[side]={"address":".".join([str(binary.read_u8(raw,i)) for i in range(4)]),"port":binary.read_u16be(port)}
            entries.append(entry)
            node=f["next"]
    return _result(entries)

def read_cache_views(space, shared_cache_map, layout, vacb_layout, view_size = 1<<18, maximum = 4096):
    """Reads a flat XP VACB pointer array into file-offset/memory mappings.

    Shared-cache fields: file_size (uint64), vacbs (pointer). VACB fields: base,
    owner, offset (uint64); low view-size bits of offset include active-count
    metadata and are masked. Owner and slot offset must agree. Null VACBs are
    explicit uncached ranges. Caller must select a verified flat-array layout;
    multi-level VACB trees are not interpreted by this reader.
    """
    if view_size<4096 or view_size>1<<24 or view_size&(view_size-1) or maximum<1 or maximum>65536:
        fail("invalid cache view bounds")
    if not shared_cache_map:
        return _bad([],0,"no shared cache map","unavailable")
    m=_read(space,shared_cache_map,layout)
    if not m["complete"]:
        return _result([],m["fault"])
    size=m["value"]["file_size"]
    count=(size+view_size-1)//view_size
    pointers=m["value"]["vacbs"]
    if count and not pointers:
        return _bad([],shared_cache_map,"null VACB array","unavailable")
    entries=[]
    for i in range(min(count,maximum)):
        ptr=_read(space,pointers+i*4,{"pointer":(0,"uint",4)})
        if not ptr["complete"]:
            return _result(entries,ptr["fault"])
        v=ptr["value"]["pointer"]
        entry={"offset":i*view_size,"size":min(view_size,size-i*view_size),"address":None}
        if v:
            item=_read(space,v,vacb_layout)
            if not item["complete"]:
                return _result(entries,item["fault"])
            f=item["value"]
            if f["owner"]!=shared_cache_map or f["offset"]&~(view_size-1)!=i*view_size or not f["base"] or f["base"]%4096 or f["base"]+entry["size"]>1<<32:
                return _bad(entries,v,"VACB owner/offset/base mismatch")
            entry["address"]=f["base"]
        entries.append(entry)
    if count>maximum:
        return _bad(entries,shared_cache_map,"cache view bound reached","limit")
    return _result(entries)

def recover_cached_file(space, views, maximum = 16<<20):
    """Returns resident bytes as offset-tagged extents plus explicit missing ranges.

    Never fills gaps with zeros or falls back to disk. Reading is page-bounded
    so later resident pages survive an earlier fault. Only complete contiguous
    recovery returns file bytes; partial recovery returns data=None and extents.
    This is a current memory view, not necessarily the durable on-disk version.
    """
    if maximum<0 or maximum>64<<20:
        fail("invalid cache recovery bound")
    extents=[]
    gaps=[]
    end=0
    for view in views["value"]:
        offset,size,address=view["offset"],view["size"],view["address"]
        if offset!=end or size<0:
            return _bad({"extents":extents,"gaps":gaps,"data":None},offset,"noncontiguous cache view inventory")
        if end+size>maximum:
            return _bad({"extents":extents,"gaps":gaps,"data":None},offset,"cache recovery byte bound reached","limit")
        end+=size
        done=0
        while done<size:
            count=min(size-done,4096-((address+done)&4095)) if address!=None else min(size-done,4096)
            p=_probe(space,address+done,count) if address!=None else _bad(b"",offset+done,"range is not cached","not-cached")
            if p["value"]:
                extents.append({"offset":offset+done,"data":p["value"]})
            if not p["complete"]:
                gaps.append({"offset":offset+done+len(p["value"]),"size":count-len(p["value"]),"fault":p["fault"]})
            done+=count
    result={"extents":extents,"gaps":gaps,"size":end,"data":None}
    if not views["complete"]:
        return _result(result,views["fault"])
    if gaps:
        return _result(result,gaps[0]["fault"])
    result["data"]=bytes_concat([e["data"] for e in extents])
    return _result(result)
