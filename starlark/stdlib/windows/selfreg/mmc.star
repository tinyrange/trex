"""Static MMC snap-in registration derived from console and PE facts."""

load(":common.star", "patch")
load(":facts.star", "class_ids", "guid_bytes")

_NULL_GUID_HEX = "0" * 32

def _description(file, module):
    for value in binary.strings(file, encoding = "utf16le", minimum = 4):
        lower = value.strip().lower()
        if ("mmc snapin" in lower or "mmc snap-in" in lower) and len(lower) <= 128:
            if not any([word in lower for word in [" failed", " failure", " error", " key"]]):
                return value
    return module.replace("\\", "/").split("/")[-1]

def _encoded_candidates(candidates):
    encoded = []
    values = []
    for candidate in candidates:
        raw = guid_bytes(candidate)
        if raw != None and hex(raw) != _NULL_GUID_HEX:
            encoded.append(raw)
            values.append(candidate.upper())
    return encoded, values

def mmc_registration_patches(file, module, candidates, pe = None):
    """Registers candidate snap-ins whose class GUIDs occur in the target PE."""
    encoded, values = _encoded_candidates(candidates)
    if not encoded:
        return []
    present = [values[index] for index in binary.view(file).find_indices(encoded)]
    if not present:
        return []
    classes = class_ids(file, pe = pe)
    served = {value.upper(): True for value in classes}
    snapins = [value for value in present if value in served]
    if not classes:
        snapins = present
    if not snapins:
        return []
    if not classes:
        classes = snapins
    description = _description(file, module)
    output = []
    seen = {}
    for class_id in classes:
        class_id = class_id.upper()
        if class_id in seen:
            continue
        seen[class_id] = True
        key = "/Classes/CLSID/" + class_id
        output.extend([
            patch(key, "(default)", description, if_absent = True),
            patch(key + "/InprocServer32", "(default)", module, if_absent = True),
            patch(key + "/InprocServer32", "ThreadingModel", "Apartment", if_absent = True),
        ])
    for class_id in snapins:
        key = "/Microsoft/MMC/SnapIns/" + class_id
        output.append(patch(key, "NameString", description, if_absent = True))
        output.append(patch(key + "/StandAlone", "(default)", "", if_absent = True))
    return output
