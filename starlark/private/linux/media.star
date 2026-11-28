"""Resolve caller-supplied Linux smoke media at the command boundary."""

def read_media(args, supported, script):
    if not args or any([name not in supported for name in args[1:]]):
        fail("usage: " + script + " <media.json> [" + "|".join(supported) + " ...]")
    filename = args[0]
    base, separator, _ = filename.rpartition("/")
    media = json.decode(open(filename), maximum = 64 << 10)
    if type(media) != "dict":
        fail("Linux media manifest must be a JSON object")
    return (media, base + separator, args[1:] or list(supported))

def media_paths(media, base, *fields):
    paths = []
    for section, name in fields:
        group = media.get(section)
        if type(group) != "dict" or type(group.get(name)) != "string" or not group[name]:
            fail("Linux media manifest requires " + section + "." + name + " as a nonempty path")
        value = group[name]
        paths.append(value if value.startswith("/") else base + value)
    return paths
