"""Pinned native store-option interpretation against explicit hive snapshots."""
load("@stdlib//windows/emulation:runner.star", native_run="run")
load("@stdlib//windows/servicing:queue_registry.star", "create_configuration_registry")

# GUID addresses, defaults, and output widths come from the pinned native
# InitializeConfigurationOptions, CQueueExecutor::Initialize and internal
# installer-service callers. Boolean options use the real Boolean overload.
_NATIVE_OPTIONS = {
    "mobile_store": (0x343aa0, 0, 4),
    "mobile_store_version": (0x343a90, 2, 4),
    "smi_hive_updates": (0x3400e8, 0, 4),
    "single_resource_ownership": (0x34a588, 0, 1),
}

def query_native_mobile_store_version(wcp_file, software):
    """Resolve executor +0x41; transaction-derived +0x40 remains unknown."""
    result = _query_native_store_options(wcp_file, software, ["mobile_store_version"])
    value = result["values"]["mobile_store_version"]
    return dict(value=value, suppress_installers=value==4, steps=result["steps"], queries=result["queries"])

def query_native_installer_options(wcp_file, software):
    """Read native HKCU service options, not transaction admission or SKU state.

    Native code owns policy precedence, value decoding, defaults and lifetime.
    MobileStore is compared with 1, not interpreted as a generic Boolean;
    MobileStoreVersion is compared with 4 by the actual executor caller.
    No POQ disposition or transaction identity is inferred from these values.
    """
    result = _query_native_store_options(wcp_file, software, sorted(_NATIVE_OPTIONS))
    values = result["values"]
    result.update(is_mobile_store=values["mobile_store"]==1, state_separated=values["mobile_store_version"]==4)
    return result

def _query_native_store_options(wcp_file, software, names):
    pe=windows.pe(wcp_file)
    if hex(digest(wcp_file,algorithm="sha256"))!="1a5d390bfbf10e24f124fd423916d15e00af06b7b8a6c982ca00ac1fd7991d85" or pe.info["machine"]!=0x8664 or pe.codeview==None or pe.codeview["key"]!="7CC21FAF1E625E052DD8ADB23E8B25F21":
        fail("native configuration requires inspected 26100.9703 WCP")
    state=dict(values={},steps=0)
    def install(m): pass
    plugin=emulator.plugin(install,name="windows.csi.configuration",state=state)
    def execute(m):
        base=[v.base for v in m.modules if v.name=="wcp.dll"][0]
        sil,key=create_configuration_registry(m,software,state,"registry",base+0x38630,base+0x33fb0)
        layout=m.allocate(size=0x160,name="read-only native configuration dependencies")
        m.write_pointer(layout+0x158,sil)
        m.write_pointer(layout+0xd8,key)
        output=m.allocate(value=binary.decode("a5a5a5a55a5a5a5a","hex"),name="configuration result and guard")
        for name in names:
            guid,default,width=_NATIVE_OPTIONS[name]
            m.write(output,binary.decode("a5a5a5a55a5a5a5a","hex"))
            result=m.call(base+(0x1ab640 if width==1 else 0xa5d90),args=[layout,base+guid,default,output])
            if result.reason!="return" or result.value!=0:
                fail("native configuration %s failed: %s value=%s detail=%s"%(name,result.reason,result.value,result.detail))
            if m.read(output+width,8-width)!=binary.decode("a5a5a5a55a5a5a5a","hex")[width:]: fail("native configuration output overflow")
            value=m.read_u8(output) if width==1 else m.read_u32le(output)
            if width==1 and value not in [0,1]: fail("native configuration returned a non-Boolean value")
            state["values"][name]=value
            state["steps"]+=result.steps
        for pointer,obj in state["registry"]["objects"].items():
            if obj["refs"]!=(1 if pointer in [sil,key] else 0): fail("native configuration registry lifetime mismatch")
        m.free(output)
        m.free(layout)
        return result
    report=native_run(wcp_file,"wcp.dll",execute=execute,plugins=[plugin],initialize=True,instruction_limit=1000000,memory_limit=128<<20)
    if report["result"].reason!="return" or report["result"].value!=0: fail("native configuration execution did not complete")
    for field in ["generated_entries","setup_actions","advpack_actions","service_activations","network_actions","process_queries","exceptions","security_actions"]:
        if report[field]: fail("native configuration produced unhandled effects: "+field)
    if any(report["registry_effects"].values()): fail("native configuration modified registry")
    return dict(values=state["values"],steps=state["steps"],queries=state["registry"]["queries"])
