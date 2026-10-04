"""Public trex Windows 1.01 input helpers.

Load with a `device = channel.extension(serial)` connection. Every call carries a
complete gesture; no host pointer or keyboard APIs are used. Screenshots are
separate host-side vm.screenshot() calls. Never retry an uncertain input call.
"""

def input_events(device, events):
    if not events or len(events) > 40:
        fail("input requires 1..40 events")
    digits = "0123456789abcdef"
    encoded = []
    for event in events:
        if len(event) != 3:
            fail("event must contain message, paramL, paramH")
        for word in event:
            if type(word) != "int" or word < 0 or word > 65535:
                fail("event words must be unsigned 16-bit integers")
            for shift in [4, 0, 12, 8]:
                encoded.append(digits[(word >> shift) & 15])
    device.input_events("".join(encoded))

def click(device, x, y, count = 1, right = False):
    if count not in [1, 2]:
        fail("click count must be 1 or 2")
    down = 0x204 if right else 0x201
    events = [(0x200, x, y)]
    for _ in range(count):
        events += [(down, x, y), (down + 1, x, y)]
    input_events(device, events)

def drag(device, points):
    if len(points) < 2 or len(points) > 38:
        fail("drag requires 2..38 desktop-pixel points")
    first, last = points[0], points[-1]
    events = [(0x200, first[0], first[1]), (0x201, first[0], first[1])]
    events += [(0x200, p[0], p[1]) for p in points[1:]]
    events.append((0x202, last[0], last[1]))
    input_events(device, events)

def key_chord(device, keys):
    """keys are (virtual_key, scan_code) pairs, pressed then released in reverse."""
    input_events(device, [(0x100, vk, scan) for vk, scan in keys] + [(0x101, vk, scan) for vk, scan in reversed(keys)])

# US keyboard layout used by this Windows 1.01 recipe. Policy, not text injection:
# all characters are actual virtual-key down/up pairs translated by Windows.
_SCAN = {"q":16,"w":17,"e":18,"r":19,"t":20,"y":21,"u":22,"i":23,"o":24,"p":25,
         "a":30,"s":31,"d":32,"f":33,"g":34,"h":35,"j":36,"k":37,"l":38,
         "z":44,"x":45,"c":46,"v":47,"b":48,"n":49,"m":50,
         "1":2,"2":3,"3":4,"4":5,"5":6,"6":7,"7":8,"8":9,"9":10,"0":11,
         " ":57,".":52,"-":12}

def type_text(device, text, pause = None):
    # Validate the whole string before sending any part. Each character/chord
    # completes with released keys; a later failed call is never replayed.
    for char in text.elems():
        if char.lower() not in _SCAN:
            fail("unsupported US-layout character " + repr(char))
    for char in text.elems():
        low = char.lower()
        vk = ord(low.upper())
        if low == ".":
            vk = 0xbe
        if low == "-":
            vk = 0xbd
        keys = [(vk, _SCAN[low])]
        if char != low:
            keys = [(0x10, 0x2a)] + keys
        key_chord(device, keys)
        if pause != None:
            pause(0.12)

def draw_demo(device, pause = None):
    """Draw once; optional pause(seconds) paces completed gestures, not playback."""
    def wait(seconds):
        if pause != None:
            pause(seconds)

    def demo_click(x, y, count = 1):
        click(device, x, y, count = count)
        wait(0.4)

    def demo_drag(points):
        drag(device, points)
        wait(0.65)

    def demo_text(text):
        type_text(device, text, pause = pause)
        wait(0.5)

    if device.ping() != "Windows Win16 extension v1":
        fail("unexpected endpoint")
    launched = device.launch("C:\\WINDOWS\\PAINT.EXE", "")
    if launched["instance"] < 32:
        fail("Paint launch was not accepted")
    wait(1.5)
    # On this fresh image Executive is the upper tile. Windows 1.01's title
    # double-click iconifies it, allowing Paint to occupy the full workspace.
    demo_click(340, 8, count = 2)
    demo_click(240, 53) # pencil
    demo_drag([(130,263),(174,247),(211,220),(243,210),(270,207),(287,182),
        (297,146),(353,146),(371,158),(371,190),(341,190),(341,207),(319,210),
        (306,230),(303,245),(316,262),(316,290),(294,290),(294,269),(281,253),
        (268,269),(268,290),(246,290),(246,264),(228,247),(205,260),(167,270),(130,263)])
    demo_drag([(341,190),(348,196),(354,190),(360,196),(367,190)])
    demo_drag([(320,218),(337,220),(337,229),(329,229),(329,225),(316,223)])
    demo_drag([(353,162),(358,162),(358,167),(353,167),(353,162)])
    demo_drag([(280,216),(274,225),(268,233)])
    demo_drag([(114,294),(358,294)])
    # Sun, drawn with the ellipse tool; then return to pencil for rays.
    demo_click(486, 53)
    demo_drag([(119,164),(139,164)])
    demo_click(240, 53)
    for points in [[(118,131),(118,139)],[(118,187),(118,195)],[(83,163),(92,163)],
                   [(145,163),(154,163)],[(93,139),(99,145)],[(139,181),(145,187)]]:
        demo_drag(points)
    # Native keyboard proof inside Paint itself, not a pre-rendered label.
    demo_click(199, 53) # text tool
    demo_click(419, 173)
    demo_text("TREX")
    demo_click(419, 200)
    demo_text("Windows 1.01")
    demo_click(419, 227)
    demo_text("Native agent input")
    demo_click(240, 53) # finish text editing
    input_events(device, [(0x200,610,300)])
    if device.ping() != "Windows Win16 extension v1":
        fail("endpoint did not survive drawing")
    return {"native_mouse": True, "native_keyboard": True, "paint_launch": launched["instance"]}
