"""User-profile layout and locale defaults."""
SYSTEM_ROOT = "/ReactOS"

def international_profile_patches():
    """Returns the default English locale and keyboard preferences."""
    intl = "/Control Panel/International"
    values = {
        "Locale": "00000c09",
        "NumShape": "1",
        "iCalendarType": "1",
        "iCountry": "61",
        "iCurrDigits": "2",
        "iCurrency": "0",
        "iDate": "1",
        "iDigits": "2",
        "iFirstDayOfWeek": "0",
        "iFirstWeekOfYear": "0",
        "iLZero": "1",
        "iMeasure": "0",
        "iNegCurr": "1",
        "iNegNumber": "1",
        "iTLZero": "0",
        "iTime": "0",
        "iTimePrefix": "0",
        "s1159": "AM",
        "s2359": "PM",
        "sCountry": "Australia",
        "sCurrency": "$",
        "sDate": "/",
        "sDecimal": ".",
        "sGrouping": "3;0",
        "sLanguage": "ENA",
        "sList": ",",
        "sLongDate": "dddd, d MMMM yyyy",
        "sMonDecimalSep": ".",
        "sMonGrouping": "3;0",
        "sMonThousandSep": ",",
        "sNativeDigits": "0123456789",
        "sNegativeSign": "-",
        "sPositiveSign": "",
        "sShortDate": "d/MM/yyyy",
        "sThousand": ",",
        "sTime": ":",
        "sTimeFormat": "h:mm:ss tt",
    }
    patches = []
    for name, value in values.items():
        patches.append({"key": intl, "name": name, "type": "REG_SZ", "value": value})
    patches.append({"key": intl + "/Geo", "name": "Nation", "type": "REG_SZ", "value": "12"})
    return patches

def profile_hive(default_user_hive, profile_path):
    """Builds a user hive with profile-relative shell folders and locale policy."""
    explorer = "/Software/Microsoft/Windows/CurrentVersion/Explorer"
    shell_folders = explorer + "/Shell Folders"
    user_shell_folders = explorer + "/User Shell Folders"
    colors = {
        "Scrollbar": "212 208 200",
        "Background": "33 87 141",
        "ActiveTitle": "255 255 255",
        "InactiveTitle": "65 65 65",
        "Menu": "255 255 255",
        "Window": "255 255 255",
        "WindowFrame": "0 0 0",
        "MenuText": "0 0 0",
        "WindowText": "0 0 0",
        "TitleText": "0 0 0",
        "ActiveBorder": "212 208 200",
        "InactiveBorder": "212 208 200",
        "AppWorkSpace": "128 128 128",
        "Hilight": "230 230 230",
        "HilightText": "0 0 0",
        "ButtonFace": "240 240 240",
        "ButtonShadow": "162 162 162",
        "GrayText": "172 168 153",
        "ButtonText": "0 0 0",
        "InactiveTitleText": "180 180 180",
        "ButtonHilight": "255 255 255",
        "ButtonDkShadow": "162 162 162",
        "ButtonLight": "241 239 226",
        "InfoText": "0 0 0",
        "InfoWindow": "255 255 225",
        "ButtonAlternateFace": "181 181 181",
        "HotTrackingColor": "0 0 128",
        "GradientActiveTitle": "255 255 255",
        "GradientInactiveTitle": "240 240 240",
        "MenuHilight": "220 220 220",
        "MenuBar": "239 238 243",
    }
    absolute = {
        "Administrative Tools": profile_path + "\\Start Menu\\Programs\\Administrative Tools",
        "AppData": profile_path + "\\Application Data",
        "Cache": profile_path + "\\Local Settings\\Temporary Internet Files",
        "Cookies": profile_path + "\\Cookies",
        "Desktop": profile_path + "\\Desktop",
        "Favorites": profile_path + "\\Favorites",
        "Fonts": "C:\\ReactOS\\Fonts",
        "History": profile_path + "\\Local Settings\\History",
        "Local AppData": profile_path + "\\Local Settings\\Application Data",
        "Local Settings": profile_path + "\\Local Settings",
        "My Music": profile_path + "\\My Documents\\My Music",
        "My Pictures": profile_path + "\\My Documents\\My Pictures",
        "My Video": profile_path + "\\My Documents\\My Videos",
        "NetHood": profile_path + "\\NetHood",
        "Personal": profile_path + "\\My Documents",
        "PrintHood": profile_path + "\\PrintHood",
        "Programs": profile_path + "\\Start Menu\\Programs",
        "Recent": profile_path + "\\Recent",
        "SendTo": profile_path + "\\SendTo",
        "Start Menu": profile_path + "\\Start Menu",
        "Startup": profile_path + "\\Start Menu\\Programs\\Startup",
        "Templates": profile_path + "\\Templates",
    }
    expandable = {
        "Administrative Tools": "%USERPROFILE%\\Start Menu\\Programs\\Administrative Tools",
        "AppData": "%USERPROFILE%\\Application Data",
        "Cache": "%USERPROFILE%\\Local Settings\\Temporary Internet Files",
        "Cookies": "%USERPROFILE%\\Cookies",
        "Desktop": "%USERPROFILE%\\Desktop",
        "Favorites": "%USERPROFILE%\\Favorites",
        "Fonts": "C:\\ReactOS\\Fonts",
        "History": "%USERPROFILE%\\Local Settings\\History",
        "Local AppData": "%USERPROFILE%\\Local Settings\\Application Data",
        "Local Settings": "%USERPROFILE%\\Local Settings",
        "My Music": "%USERPROFILE%\\My Documents\\My Music",
        "My Pictures": "%USERPROFILE%\\My Documents\\My Pictures",
        "My Video": "%USERPROFILE%\\My Documents\\My Videos",
        "NetHood": "%USERPROFILE%\\NetHood",
        "Personal": "%USERPROFILE%\\My Documents",
        "PrintHood": "%USERPROFILE%\\PrintHood",
        "Programs": "%USERPROFILE%\\Start Menu\\Programs",
        "Recent": "%USERPROFILE%\\Recent",
        "SendTo": "%USERPROFILE%\\SendTo",
        "Start Menu": "%USERPROFILE%\\Start Menu",
        "Startup": "%USERPROFILE%\\Start Menu\\Programs\\Startup",
        "Templates": "%USERPROFILE%\\Templates",
    }
    patches = []
    for patch in international_profile_patches():
        patches.append(patch)
    for name, value in colors.items():
        patches.append({"key": "/Control Panel/Colors", "name": name, "type": "REG_SZ", "value": value})
    for patch in [
        {"key": "/Keyboard Layout/Preload", "name": "1", "type": "REG_SZ", "value": "d0000c09"},
        {"key": "/Keyboard Layout/Substitutes", "name": "d0000c09", "type": "REG_SZ", "value": "00000409"},
        {"key": "/Keyboard Layout/Toggle", "name": "Hotkey", "type": "REG_SZ", "value": "1"},
        {"key": "/Keyboard Layout/Toggle", "name": "Language Hotkey", "type": "REG_SZ", "value": "1"},
        {"key": "/Keyboard Layout/Toggle", "name": "Layout Hotkey", "type": "REG_SZ", "value": "2"},
    ]:
        patches.append(patch)
    for name, value in absolute.items():
        patches.append({"key": shell_folders, "name": name, "type": "REG_SZ", "value": value})
    for name, value in expandable.items():
        patches.append({"key": user_shell_folders, "name": name, "type": "REG_EXPAND_SZ", "value": value})
    patches.append({"key": explorer + "/Streams", "name": "(default)", "type": "REG_SZ", "value": ""})
    return windows.patch_hive(default_user_hive, patches)

PROFILE_DIRECTORIES = [
    "", "Application Data", "Application Data/Microsoft", "Application Data/Microsoft/Internet Explorer",
    "Application Data/Microsoft/Internet Explorer/Quick Launch", "Cookies", "Desktop", "Favorites",
    "Local Settings", "Local Settings/Application Data", "Local Settings/History", "Local Settings/Temp",
    "Local Settings/Temporary Internet Files", "My Documents", "My Documents/My Music",
    "My Documents/My Pictures", "My Documents/My Videos", "NetHood", "PrintHood", "Recent", "SendTo",
    "Start Menu", "Start Menu/Programs", "Start Menu/Programs/Administrative Tools",
    "Start Menu/Programs/Startup", "Templates",
]

def add_profile_skeleton(root, default_user_hive, users = ["Administrator"]):
    """Builds each declared profile from one directory and hive specification."""
    root.mkdir("/Documents and Settings")
    profiles = ["/Documents and Settings/" + name for name in users + ["Default User", "NetworkService"]]
    profiles.append(SYSTEM_ROOT + "/system32/config/systemprofile")
    for base in profiles:
        for relative in PROFILE_DIRECTORIES:
            mkdir_tree(root, path.join(base, relative))
        hive = profile_hive(default_user_hive, "C:" + base.replace("/", "\\"))
        root.write(base + "/NTUSER.DAT", hive)
        root.write(base + "/ntuser.dat.LOG", "")
    for relative in ["", "Application Data", "Desktop", "My Documents", "Start Menu", "Start Menu/Programs", "Start Menu/Programs/Administrative Tools", "Start Menu/Programs/Startup", "Templates"]:
        mkdir_tree(root, path.join("/Documents and Settings/All Users", relative))
    event_log = windows.empty_event_log()
    for name in ["AppEvent.Evt", "SecEvent.Evt", "SysEvent.Evt"]:
        root.write(path.join(SYSTEM_ROOT, "system32/config", name), event_log)
    for name in ["DEFAULT.LOG", "SAM.LOG", "SECURITY.LOG", "SOFTWARE.LOG", "SYSTEM.LOG"]:
        root.write(path.join(SYSTEM_ROOT, "system32/config", name), "")

def mkdir_tree(root, name):
    """Ensures all ancestors of an image directory exist."""
    current = ""
    for part in name.split("/"):
        if part == "":
            continue
        current = current + "/" + part
        root.mkdir(current)
