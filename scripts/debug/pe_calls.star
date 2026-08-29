"""Bounded PE relative-call lookup for live reverse-engineering sessions."""

def relative_call_sites(image, target_rva, maximum = 4096):
    parsed = windows.pe(image)
    source = binary.view(image)
    output = []
    for section in parsed.sections:
        if section["name"] != ".text":
            continue
        start = section["raw_offset"]
        end = start + section["raw_size"]
        cursor = start
        while cursor + 5 <= end:
            cursor = source.find(b"\xe8", start = cursor)
            if cursor < 0 or cursor + 5 > end:
                break
            displacement = binary.read_u32le(source, cursor + 1)
            if displacement & 0x80000000:
                displacement -= 0x100000000
            call_rva = section["virtual_address"] + cursor - start
            if (call_rva + 5 + displacement) & 0xffffffff == target_rva:
                output.append(call_rva)
                if len(output) >= maximum:
                    fail("relative-call result exceeds its configured limit")
            cursor += 1
    return output
