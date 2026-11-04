"""Pinned native executor eligibility probe, not a complete execution planner."""
load("@stdlib//windows/emulation:runner.star", native_run="run")
load("@stdlib//windows/servicing:queue_registry.star", "create_executor_registry")

def determine_per_user_eligibility(wcp_file, software, identifiers, force_per_user, suppress_installers, instruction_limit=1000000):
    """Run DetermineIfHKCUShouldRun against explicit target inputs.

    The two booleans are CQueueExecutor fields +0x40 (Initialize flags bit 2)
    and +0x41 (store option equals 4). Neither is inferred here. Callers must
    establish them for the actual transaction before applying these results.
    A True result only passes this gate; it does not prove complete eligibility,
    execution, an installed inventory, or a committed CBS transaction.
    """
    pe=windows.pe(wcp_file)
    if hex(digest(wcp_file,algorithm="sha256"))!="1a5d390bfbf10e24f124fd423916d15e00af06b7b8a6c982ca00ac1fd7991d85" or pe.info["machine"]!=0x8664 or pe.codeview==None or pe.codeview["key"]!="7CC21FAF1E625E052DD8ADB23E8B25F21":
        fail("native eligibility requires the inspected 26100.9703 WCP")
    if type(force_per_user)!="bool" or type(suppress_installers)!="bool" or not identifiers or len(identifiers)>128 or instruction_limit<1 or instruction_limit>1000000:
        fail("invalid native eligibility inputs")
    guids=[]
    for identifier in identifiers:
        if len(identifier)!=32: fail("invalid native installer identifier")
        guids.append(binary.decode(identifier,"hex"))
    state=dict(results=[])
    def install(m): pass
    plugin=emulator.plugin(install,name="windows.csi.executor.eligibility",state=state)
    def execute(m):
        base=[v.base for v in m.modules if v.name=="wcp.dll"][0]
        sil=create_executor_registry(m,{"SOFTWARE":software},state,"registry",base+0x38630,base+0x33fb0)
        executor=m.allocate(size=0x48,name="native eligibility inputs")
        m.write(executor+0x40,binary.concat([binary.u8(1 if force_per_user else 0),binary.u8(1 if suppress_installers else 0)]).bytes())
        output=m.allocate(size=8,name="native eligibility result and guard")
        for identifier,guid in zip(identifiers,guids):
            argument=m.allocate(value=guid,name="native installer identifier")
            m.write(output,binary.decode("a5a5a5a5a5a5a5a5","hex"))
            result=m.call(base+0x1e77f4,args=[executor,sil,argument,output])
            if result.reason!="return" or result.value!=0:
                fail("native eligibility failed: %s value=%s steps=%s detail=%s"%(result.reason,result.value,result.steps,result.detail))
            if hex(m.read(output+1,7))!="a5a5a5a5a5a5a5" or m.read_u8(output) not in [0,1]: fail("invalid native eligibility output")
            state["results"].append(dict(installer=identifier,should_run=m.read_u8(output)==1,steps=result.steps))
            m.free(argument)
        # Every opened key must have been released; the caller owns the SIL.
        if any([o["refs"] for p,o in state["registry"]["objects"].items() if p!=sil]): fail("native eligibility retained registry keys")
        return result
    report=native_run(wcp_file,"wcp.dll",execute=execute,plugins=[plugin],initialize=True,instruction_limit=instruction_limit,memory_limit=128<<20)
    if report["result"].reason!="return" or report["result"].value!=0:
        result=report["result"]
        fail("native eligibility execution failed: %s value=%s steps=%s detail=%s"%(result.reason,result.value,result.steps,result.detail))
    for field in ["generated_entries","setup_actions","advpack_actions","service_activations","network_actions","process_queries","exceptions","security_actions"]:
        if report[field]: fail("native eligibility produced unhandled effects: "+field)
    if any(report["registry_effects"].values()): fail("native eligibility modified registry")
    return dict(results=state["results"],queries=state["registry"]["queries"],force_per_user=force_per_user,suppress_installers=suppress_installers)
