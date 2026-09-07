"""INF-declared shortcuts and installed-file lookup."""
load(":profiles.star", "mkdir_tree")

def shortcut_folder_path(folder_id, relative, user = "Administrator"):
    """Resolves an INF shortcut folder ID for the selected user."""
    if folder_id == "0":
        base = "/Documents and Settings/Administrator/Desktop"
    elif folder_id == "2":
        base = "/Documents and Settings/Administrator/Start Menu/Programs"
    elif folder_id == "26":
        base = "/Documents and Settings/Administrator/Application Data"
    elif folder_id == "47":
        base = "/Documents and Settings/All Users/Start Menu/Programs/Administrative Tools"
    else:
        base = "/Documents and Settings/All Users/Start Menu/Programs"
    base = base.replace("/Documents and Settings/Administrator/", "/Documents and Settings/" + user + "/")
    if relative == "":
        return base
    return path.join(base, path.from_windows(relative))

def safe_shortcut_name(name):
    """Replaces characters that cannot occur in a Windows shortcut filename."""
    for c in ["\\", "/", ":", "*", "?", "\"", "<", ">", "|"]:
        name = name.replace(c, "_")
    return name

def shortcut_int(value):
    """Decodes the small icon-index range used by the media shortcut policy."""
    if value == "1":
        return 1
    if value == "2":
        return 2
    if value == "3":
        return 3
    if value == "4":
        return 4
    if value == "5":
        return 5
    return 0

def installed_windows_path(reactos_inf, filename):
    """Looks up the first installed Windows path for a media filename."""
    lower = filename.lower()
    for name, dirs in reactos_inf["SourceFiles"].items():
        if name.lower() != lower or len(dirs) == 0:
            continue
        dir_id = dirs[0]
        if dir_id not in reactos_inf["Directories"]:
            return ""
        values = reactos_inf["Directories"][dir_id]
        if len(values) == 0:
            return ""
        rel = values[0]
        if rel == "\\":
            return "C:\\ReactOS\\" + filename
        return "C:\\ReactOS\\" + rel + "\\" + filename
    return ""

def installed_file_size(cab, reactos_inf, filename):
    """Returns the size of a CAB-backed installed file, or zero if absent."""
    lower = filename.lower()
    for name, _ in reactos_inf["SourceFiles"].items():
        if name.lower() == lower:
            return cab["/" + name].size
    return 0

def windows_base_name(name):
    """Returns the final backslash-separated filename."""
    parts = name.split("\\")
    return parts[len(parts) - 1]

def expand_shortcut_path(value, reactos_inf, user = "Administrator"):
    """Expands the media shortcut variables for the selected user."""
    out = value
    replacements = {
        "SystemRoot": "C:\\ReactOS",
        "HOMEDRIVE": "C:",
        "HOMEPATH": "\\Documents and Settings\\" + user,
        "16422": "C:\\Program Files",
    }
    for k, v in replacements.items():
        out = out.replace("%" + k + "%", v)
    if out.lower() == "c:\\program files\\internet explorer\\iexplore.exe":
        installed = installed_windows_path(reactos_inf, "iexplore.exe")
        if installed != "":
            return installed
    return out

def shortcut_rows(section):
    """Normalizes repeated INF shortcut rows without losing their order."""
    rows = []
    for _, row in section.items():
        if len(row) > 0 and type(row[0]) == "list":
            for nested in row:
                rows.append(nested)
        else:
            rows.append(row)
    return rows

def add_shortcuts_from_inf(root, cab, shortcut_inf, reactos_inf, user = "Administrator"):
    """Constructs shell links from media declarations for the selected user."""
    folders = shortcut_inf["ShortcutFolders"]
    for section_name, folder_values in folders.items():
        if section_name not in shortcut_inf:
            continue
        folder_id = folder_values[0]
        relative = ""
        if len(folder_values) > 1:
            relative = folder_values[1]
        folder = shortcut_folder_path(folder_id, relative, user)
        mkdir_tree(root, folder)
        for row in shortcut_rows(shortcut_inf[section_name]):
            if len(row) < 2:
                continue
            target = expand_shortcut_path(row[0], reactos_inf, user)
            title = row[1]
            description = ""
            if len(row) > 2:
                description = row[2]
            icon_index = 0
            if len(row) > 3:
                icon_index = shortcut_int(row[3])
            working_dir = ""
            if len(row) > 4:
                working_dir = expand_shortcut_path(row[4], reactos_inf, user)
            target_size = installed_file_size(cab, reactos_inf, windows_base_name(target))
            root.write(
                path.join(folder, safe_shortcut_name(title) + ".lnk"),
                windows.shortcut(
                    target=target,
                    description=description,
                    working_dir=working_dir,
                    icon_location=target,
                    icon_index=icon_index,
                    target_size=target_size,
                    system_root="C:\\ReactOS",
                ),
            )
