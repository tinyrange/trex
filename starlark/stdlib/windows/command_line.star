"""Microsoft command-line parsing shared by Windows process models."""

def command_line_arguments(value):
    """Splits a Microsoft CRT command line, including backslash-quote runs."""
    output = []
    index = 0
    while index < len(value):
        while index < len(value) and value[index] in [" ", "\t"]:
            index += 1
        if index >= len(value):
            break
        argument = ""
        quoted = False
        while index < len(value):
            if value[index] in [" ", "\t"] and not quoted:
                break
            slashes = 0
            while index < len(value) and value[index] == "\\":
                slashes += 1
                index += 1
            if index < len(value) and value[index] == '"':
                argument += "\\" * (slashes // 2)
                if slashes % 2:
                    argument += '"'
                elif quoted and index + 1 < len(value) and value[index + 1] == '"':
                    argument += '"'
                    index += 1
                else:
                    quoted = not quoted
                index += 1
                continue
            argument += "\\" * slashes
            if index >= len(value) or (value[index] in [" ", "\t"] and not quoted):
                break
            argument += value[index]
            index += 1
        output.append(argument)
        while index < len(value) and value[index] in [" ", "\t"]:
            index += 1
    return output
