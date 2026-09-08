package starlarkfrontend

import "testing"

func TestWindowsMemoryContext(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows:memory_context.star", "read_process_context", "describe_vad", "walk_frames", "read_thread_context", "read_object_handles", "read_key_path", "read_object_path", "read_endpoints", "read_cache_views", "recover_cached_file", "module_at")
def check(value, reason):
    if not value:
        fail(reason)
def run():
    b=binary.builder()
    b.reserve(32768)
    def space():
        return windows.memory_image(b.file())
    # Relative process-parameter strings, then normalized pointers.
    b.patch_u32le(16,32)
    b.patch_u32le(32,64)
    b.patch_u16le(68,2)
    b.patch_u16le(70,2)
    b.patch_u32le(72,16)
    b.patch_u16le(80,65)
    process={"peb":(0,"uint",4)}
    peb={"parameters":(0,"uint",4)}
    params={"flags":(0,"uint",4),"command_line":(4,"unicode",8)}
    p=read_process_context(space(),space(),16,process,peb,params)
    check(p["complete"] and p["value"]["parameters"]["command_line"]=="A","relative Unicode")
    b.patch_u32le(64,1)
    b.patch_u32le(72,80)
    check(read_process_context(space(),space(),16,process,peb,params)["complete"],"normalized Unicode")
    b.patch_u32le(72,0xffffffff)
    check(not read_process_context(space(),space(),16,process,peb,params)["complete"],"Unicode overflow")
    # Private VADs do not dereference the nonexistent long-VAD tail.
    flags={"private_bit":31,"protection_shift":24,"protection_mask":31,"protections":{4:"read-write"},"control_area_offset":24}
    vad={"address":0xfffffffc,"fields":{"flags":0x84000000}}
    r=describe_vad(space(),vad,flags,{"file":(0,"uint",4)},{"type":(0,"uint",2)})
    check(r["complete"] and r["value"]["private"] and r["value"]["protection"]=="read-write","short private VAD")
    vad={"address":128,"fields":{"flags":0x04000000}}
    b.patch_u32le(152,160)
    b.patch_u32le(160,192)
    b.patch_u16le(192,5)
    check(describe_vad(space(),vad,flags,{"file":(0,"uint",4)},{"type":(0,"uint",2)})["complete"],"mapped VAD backing")
    b.patch_u16le(192,4)
    check(not describe_vad(space(),vad,flags,{"file":(0,"uint",4)},{"type":(0,"uint",2)})["complete"],"wrong file type")
    # Monotonic EBP frames: never scan random words as return addresses.
    b.patch_u32le(256,272)
    b.patch_u32le(260,0x401000)
    b.patch_u32le(276,0x402000)
    modules=[{"base":0x400000,"size":0x10000,"name":"test.exe"}]
    frames=walk_frames(space(),256,256,512,modules)
    check(frames["complete"] and len(frames["value"])==2 and frames["value"][0]["modules"][0]["rva"]==4096,"EBP chain")
    check(not walk_frames(space(),256,256,512,maximum=1)["complete"],"frame bound")
    b.patch_u32le(272,256)
    check(not walk_frames(space(),256,256,512)["complete"],"cyclic stack")
    check(not walk_frames(space(),252,256,512)["complete"],"stack bounds")
    check(module_at(0x500000,modules)==[],"unknown module")
    # An absent trap preserves independently readable thread state.
    b.patch_u32le(384,5)
    thread_layout={"state":(0,"uint",4),"start":(4,"uint",4),"trap":(8,"uint",4),"teb":(12,"uint",4),"stack_limit":(16,"uint",4),"stack_base":(20,"uint",4)}
    t=read_thread_context(space(),space(),384,thread_layout,{}, {},{5:"waiting"})
    check(t["complete"] and t["value"]["state"]=="waiting" and not t["value"]["stack"]["complete"],"independent thread metadata")
    # Registry names use zero-extended compressed characters, not UTF-8 guessing.
    b.patch_u32le(512,544)
    b.patch_u32le(516,600)
    b.patch_u32le(548,620)
    b.patch_u16le(600,1)
    b.patch_u16le(602,1)
    b.patch(604,b"A")
    b.patch_u16le(620,1)
    b.patch_u16le(622,1)
    b.patch(624,b"B")
    key_layout={"parent":(0,"uint",4),"name":(4,"uint",4)}
    name_layout={"compressed":(0,"uint",2),"length":(2,"uint",2)}
    path=read_key_path(space(),512,key_layout,name_layout,4)
    check(path["complete"] and path["value"]==["A","B"],"KCB path")
    b.patch_u32le(544,512)
    check(not read_key_path(space(),512,key_layout,name_layout,4)["complete"],"KCB cycle")
    # Named object headers, preserved unknown types, and directory ancestry.
    b.patch_u32le(704,800)
    b.patch_u32le(708,16)
    b.patch_u16le(800,10)
    b.patch_u16le(802,10)
    b.patch_u32le(804,840)
    b.patch(840,b"E\x00v\x00e\x00n\x00t\x00")
    b.patch_u16le(692,2)
    b.patch_u16le(694,2)
    b.patch_u32le(696,860)
    b.patch_u16le(860,65)
    b.patch_u32le(728,1)
    handles={"value":[{"object_header":704,"handle":4,"access":3}],"complete":True,"fault":None}
    h=read_object_handles(space(),handles,{"type":(0,"uint",4),"name_offset":(4,"uint",4)},{"name":(0,"unicode",8)},{"directory":(0,"uint",4),"name":(4,"unicode",8)},24,{"Event":{"signal":(0,"uint",4)}})
    check(h["complete"] and h["value"][0]["type"]=="Event" and h["value"][0]["name"]["value"]["name"]=="A" and h["value"][0]["body"]["value"]["signal"]==1,"named Event handle")
    path=read_object_path(space(),728,24,{"name_offset":(4,"uint",4)},{"directory":(0,"uint",4),"name":(4,"unicode",8)})
    check(path["complete"] and path["value"]==["A"],"object path")
    b.patch_u32le(688,728)
    check(not read_object_path(space(),728,24,{"name_offset":(4,"uint",4)},{"directory":(0,"uint",4),"name":(4,"unicode",8)})["complete"],"directory cycle")
    h=read_object_handles(space(),handles,{"type":(0,"uint",4),"name_offset":(4,"uint",4)},{"name":(0,"unicode",8)},{"directory":(0,"uint",4),"name":(4,"unicode",8)},24)
    check(h["complete"] and h["value"][0]["body"]==None,"unrequested type body preserved")
    # Positive IPv4/port decoding and endpoint-chain corruption.
    b.patch_u32le(1024,1100)
    b.patch_u32le(1104,42)
    b.patch(1108,b"\x7f\x00\x00\x01\x1f\x90\x08\x08\x08\x08\x00\x35")
    ep_layout={"next":(0,"uint",4),"pid":(4,"uint",4),"local_address":(8,"bytes",4),"local_port":(12,"bytes",2),"remote_address":(14,"bytes",4),"remote_port":(18,"bytes",2)}
    ep=read_endpoints(space(),1024,2,ep_layout)
    check(ep["complete"] and ep["value"][0]["local"]=={"address":"127.0.0.1","port":8080} and ep["value"][0]["remote"]["port"]==53,"network order")
    b.patch_u32le(1100,1100)
    check(not read_endpoints(space(),1024,2,ep_layout)["complete"],"endpoint cycle")
    check(read_endpoints(space(),0,0,ep_layout)["fault"]["kind"]=="unavailable","uninitialized is not empty")
    # Self-consistent flat VACBs and sparse byte recovery after an absent page.
    b.patch_u32le(2048,8192)
    b.patch_u32le(2056,2080)
    b.patch_u32le(2080,2100)
    b.patch_u32le(2084,2120)
    b.patch_u32le(2100,8192)
    b.patch_u32le(2104,2048)
    b.patch_u32le(2120,12288)
    b.patch_u32le(2124,2048)
    b.patch_u32le(2128,4096)
    cache_layout={"file_size":(0,"uint",8),"vacbs":(8,"uint",4)}
    vacb_layout={"base":(0,"uint",4),"owner":(4,"uint",4),"offset":(8,"uint",8)}
    views=read_cache_views(space(),2048,cache_layout,vacb_layout,view_size=4096)
    check(views["complete"] and len(views["value"])==2,"VACB views")
    check(recover_cached_file(space(),views)["complete"],"complete cache")
    sparse=windows.memory_image(b.file(),ranges=[(0,0,8192),(12288,12288,4096)])
    recovered=recover_cached_file(sparse,views)
    check(not recovered["complete"] and recovered["value"]["data"]==None and recovered["value"]["gaps"][0]["offset"]==0 and recovered["value"]["extents"][0]["offset"]==4096,"later pages survive gaps")
    check(not recover_cached_file(space(),views,maximum=4096)["complete"],"cache byte bound")
    b.patch_u32le(2104,0)
    check(not read_cache_views(space(),2048,cache_layout,vacb_layout,view_size=4096)["complete"],"VACB owner mismatch")
    # A null VACB is unavailable data, not a zero-filled file.
    b.patch_u32le(2080,0)
    views=read_cache_views(space(),2048,cache_layout,vacb_layout,view_size=4096)
    check(views["complete"] and recover_cached_file(space(),views)["value"]["gaps"][0]["fault"]["kind"]=="not-cached","uncached view")
run()
`)
}
