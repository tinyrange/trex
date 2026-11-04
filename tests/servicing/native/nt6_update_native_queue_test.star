"""Explicit-media controls for the pinned native WCP queue deriver."""
load("@stdlib//windows/servicing:native_queue.star", "derive_offline_queue")
load("@stdlib//windows/servicing:events_native.star", "events_jobs_from_queue")

_EVENTS="2bfdb93b1e359c4bb1fced0758805998"

def verify_native_queue(wcp,old,new,derive=derive_offline_queue):
    if hex(digest(new,algorithm="sha256"))!="20d3116cebed714670541c25b500984352a75878ac4f42fc202f6f1c9691c9ed":
        fail("native queue regression requires the inspected FunDisc 26100.9549 manifest")
    original=[hex(digest(f,algorithm="sha256")) for f in [old,new]]
    def events(result):
        return [e for e in result["entries"] if e["installer"]==_EVENTS]
    pair=derive(wcp,[(old,new)])
    if events(pair) or not pair["inspection_required"] or pair["inspection_inventory_supplied"]:
        fail("missing inspection inventory was mistaken for a completed Events queue")
    added=binary.concat([new.read().replace('name="FunDisc"','name="Native-Queue-Added"')])
    resident=binary.concat([new.read().replace('name="FunDisc"','name="Native-Queue-Resident"')])
    combined=derive(wcp,[(old,new),(None,added)],inspect_manifests=[resident])
    entries=events(combined)
    if [(e["operation"],e["phase"]) for e in entries]!=[(2,9),(4,9),(4,9)]:
        fail("native active/inspection queue admission mismatch: "+str(entries))
    if entries[0]["after"]!=(1,"after") or entries[0]["before"]!=None or entries[0]["inspect"]!=None:
        fail("native added-component identity ownership mismatch")
    if [e["inspect"] for e in entries[1:]]!=[(0,"before"),(0,"inspect")]:
        fail("native provisional/installed inspection identities lost")
    if not combined["inspection_required"] or not combined["inspection_inventory_supplied"]:
        fail("native inspection inventory evidence lost")
    refused=testing.attempt(events_jobs_from_queue,args=[pair,[(old,new)]])
    if refused.ok or "inspection inventory" not in refused.error: fail("incomplete native queue was dispatched")
    jobs=events_jobs_from_queue(combined,[(old,new),(None,added)],[resident])
    if jobs!=[(1,added),(3,old),(3,resident)]: fail("native smart operation/identity mapping differs")
    # Non-delta phases distinguish argument reversal even when unchanged
    # Events XML produces the same provisional operation in either order.
    fve=binary.concat([new.read().replace("</assembly>",'<fveUpdateAI fveCommand="bootmgr" /></assembly>')])
    for pair,operation,phase,side in [((None,fve),3,10,"after"),((fve,None),1,8,"before")]:
        result=derive(wcp,[pair])
        rows=[e for e in result["entries"] if e["installer"]=="bacf4a084f718a4da69afe4e9c8ce62d"]
        if len(rows)!=1 or rows[0]["operation"]!=operation or rows[0]["phase"]!=phase or rows[0][side]!=(0,side):
            fail("native new/old ABI reversed install and removal: "+str(rows))
    malformed=testing.attempt(derive,args=[wcp,[(None,binary.concat(["<assembly"]))]])
    if malformed.ok or "parse" not in malformed.error: fail("malformed native queue input accepted")
    limited=testing.attempt(derive,args=[wcp,[(old,new)]],kwargs={"instruction_limit":3150000})
    if limited.ok or "instruction-limit" not in limited.error or "parse" not in limited.error:
        fail("native queue exposed a plan after incomplete parsing")
    if [hex(digest(f,algorithm="sha256")) for f in [old,new]]!=original: fail("native queue changed its source manifests")
    return dict(provisional_events_omitted_without_inventory=True,missing_inventory_explicit=True,active_events=1,inspection_events=2,identity_ownership=True,install_remove_order=True,malformed_rejected=True,instruction_limit_rejected=True,sources_unchanged=True)


def verify_native_large_queue(wcp,manifest,registry_snapshots,derive=derive_offline_queue):
    """Real unchanged Wi-Fi driver manifest that exceeds the former small bound."""
    expected="44941b50d88627d78d69dce0ee97976d52ac0e61d9bfb7d7ca63eaf4ab226545"
    if manifest.size!=8521977 or hex(digest(manifest,algorithm="sha256"))!=expected:
        fail("native large queue control requires exact dual_netwtw02.inf manifest")
    result=derive(wcp,[(None,manifest)],registry_snapshots=registry_snapshots,instruction_limit=2000000000)
    if not result["finalized"] or result["entries"] or result["parse_steps"]!=1212224926:
        fail("native large manifest control did not complete its established path")
    if hex(digest(manifest,algorithm="sha256"))!=expected: fail("native large manifest source changed")
    return dict(parse_steps=result["parse_steps"],entries=0,finalized=True)
