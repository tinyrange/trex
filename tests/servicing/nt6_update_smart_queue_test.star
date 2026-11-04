"""Operation ordering and admission boundaries shared by native smart installers."""
load("//tests:testing.star", "case", "equal", "raises", "suite")
load("@stdlib//windows/servicing:smart_installer.star", "smart_jobs_from_queue")
load("@stdlib//windows/servicing:events_native.star", "events_jobs_from_queue")

_PROFILES={"appx":"bab1aaf1e06e944dbaebc9fd61f365cf","events":"2bfdb93b1e359c4bb1fced0758805998","network-drivers":"80f211a12359c0479a68d0bafb577901","system-protection":"a39bfc2ed6788c45ac190b5b6bdae296"}

def _entry(guid,**fields):
    row=dict(installer=guid,phase=9,operation=2,flags=0,before=(0,"before"),after=(0,"after"),inspect=None)
    row.update(fields)
    return row

def _queue(entries):
    return dict(finalized=True,inspection_required=True,inspection_inventory_supplied=True,entries=entries)

def test_native_order_and_both_inspection_sources():
    old,new,resident=[binary.concat([s]) for s in ["old","new","resident"]]
    for profile,guid in _PROFILES.items():
        entries=[_entry(guid),_entry(guid,operation=4,before=None,after=None,inspect=(0,"before")),_entry(guid,operation=4,before=None,after=None,inspect=(0,"inspect"))]
        # Unknown installers are not silently treated as this profile's jobs.
        entries.insert(0,_entry("not-this-installer",phase=3))
        queue=_queue(entries)
        expected=[(1,new),(2,old),(3,old),(3,resident)]
        equal(smart_jobs_from_queue(queue,profile,[(old,new)],[resident]),expected)
        if profile=="events": equal(events_jobs_from_queue(queue,[(old,new)],[resident]),expected)
        equal(smart_jobs_from_queue(_queue([_entry(guid,before=None)]),profile,[(None,new)],[]),[(1,new)])
        equal(smart_jobs_from_queue(_queue([_entry(guid,after=None)]),profile,[(old,None)],[]),[(2,old)])

def test_incomplete_or_ambiguous_entries_cannot_dispatch():
    old,new=[binary.concat([s]) for s in ["old","new"]]
    for profile,guid in _PROFILES.items():
        queue=_queue([_entry(guid)])
        incomplete=dict(queue,finalized=False)
        raises(smart_jobs_from_queue,args=[incomplete,profile,[(old,new)],[]],message="finalized")
        incomplete=dict(queue,inspection_inventory_supplied=False)
        raises(smart_jobs_from_queue,args=[incomplete,profile,[(old,new)],[]],message="inspection inventory")
        raises(smart_jobs_from_queue,args=[queue,profile,[(old,new)]],message="inspection inventory")
        for changes in [dict(phase=10),dict(flags=1),dict(operation=1),dict(before=(0,"after")),dict(after=(1,"after")),dict(after=(-1,"after")),dict(inspect=(0,"inspect")),dict(before=None,after=None),dict(operation=4),dict(operation=4,before=None,after=None,inspect=(1,"inspect"))]:
            attempt=testing.attempt(smart_jobs_from_queue,args=[_queue([_entry(guid,**changes)]),profile,[(old,new)],[]])
            equal(attempt.ok,False)
        raises(smart_jobs_from_queue,args=[queue,profile,[(None,new)],[]],message="absent manifest")

TEST_SUITE=suite("nt6/update-smart-queue",[
    case("native_order_and_inspection",test_native_order_and_both_inspection_sources),
    case("reject_incomplete_or_ambiguous",test_incomplete_or_ambiguous_entries_cannot_dispatch),
])
