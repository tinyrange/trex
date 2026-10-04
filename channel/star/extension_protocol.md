# Synchronous extension wire protocol (v1)

Available offline in the public trex REPL:

    help(channel.extension)
    print(channel.extension_protocol())
    help(device)  # discovered function signatures/docs as the wire manifest

`device = channel.extension(byte_channel, timeout=5)` discovers immediately.
The channel must support deadlines. Give it exclusive ownership: do not also
read/write it or expose it through a TCP bridge. `device.close()` closes it.
Consume any device-specific readiness banner BEFORE connecting (the Windows
recipe consumes `WINEXT_READY\n`). Only trusted endpoints: no authentication,
encryption, sandboxing, reconnect, or automatic retries are supplied.

## Framing and discovery

UTF-8, literal TAB-separated fields, LF-terminated lines. CRLF is accepted;
CR counts against the line limit. No debug output, echo, or banners inside the
protocol. Flush replies. In the examples below `\t` means one actual tab and
`\n` means LF (not the two printable characters). Value string escapes are
explained separately below.

Host sends `?\n`. Device replies with:

    API\t1\t1024
    ABOUT\tsWindows 1.01 computer use
    FN\tping\tstr\tsReadiness
    END
    FN\tlaunch\tmap\tsLaunch an application
    ARG\tpath\tstr\tsWindows path
    ARG\ttail\tstr\tsCommand tail
    END
    FN\tinput_events\tnone\tsComplete bounded native input gesture
    ARG\tevents\tstr\tsHex-encoded records
    END
    DONE

API fields: version (must be 1), device receive limit in bytes excluding LF
(32..1048576). Optional ABOUT appears once before functions. Repeat FN, zero
or more ARG, END; terminate with DONE. Names match
`[A-Za-z_][A-Za-z0-9_]{0,63}`, excluding Python/Starlark keywords; function
`close` is reserved. Duplicate names are invalid. Types are `any`, `none`,
`bool`, `int`, `float`, `str`, `array`, `map`. All arguments are required;
keyword arguments are reordered to declared order. Top-level types are checked.

## Calls and values

`CALL\tname` followed by one encoded value per argument gets exactly one
`OK\tvalue` or `ERR\tscode\tsmessage`. One exchange at a time. ERR is a
completed protocol exchange and leaves the connection usable, but does not
promise that the device rolled back any effects. Never blindly retry an input
error, especially `input_timeout`. Wire/I/O errors close the connection: the
outcome may be unknown. There is no transaction ID or replay protection.

Values occupy one or more tab-separated tokens:

* `n`: None. `b0`, `b1`: boolean.
* `i` followed by `-?[0-9]+`: exact integer, not converted through float.
* `f` followed by `-?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?`: finite binary64.
* `s` followed by UTF-8 text: string. Only backslash escapes `\\`, `\t`,
  `\n`, `\r` are allowed. Literal backslash must be doubled; raw ASCII controls
  (0..31,127) are forbidden. Quotes and spaces have no special meaning.
* `a<count>` then count recursively encoded values: array.
* `m<count>` then count string-key/value pairs: map. Keys must be unique.

`s`, `a0`, `m0` are empty values; counts use `[0-9]+`. For example:
`m1\tsreadings\ta2\ti23\tf24.5` represents `{"readings": [23, 24.5]}`.

Client limits: 64 KiB per received line, 1 MiB manifest, 256 functions,
64 arguments per function, nesting at most 32, outgoing call bounded by the
device's advertised receive limit. The timeout bounds a whole discovery or
call (both write and read), default 5 seconds, configurable up to 300 seconds.
Do not place operations requiring later calls inside a synchronous modal wait.
This client deliberately rejects v2/v3 (futures/streaming), not silently treating
them as v1. No host SDK or StarAgent is needed.

## Windows 1.01 native input payload

`input_events(events)` takes a hex string containing 1..40 six-byte records:
LE16(message), LE16(paramL), LE16(paramH). Hex is inside an ordinary `s` token.

* 0x0200: mouse move; 0x0201/0x0202: left down/up;
  0x0204/0x0205: right down/up. paramL=x, paramH=y in desktop pixels.
* 0x0100/0x0101: key down/up. paramL=virtual key, paramH=scan code.

Example complete left click at (100,100):

    CALL\tinput_events\ts000264006400010264006400020264006400
    OK\tn

The entire batch is validated before effects. Coordinates must be in bounds;
press/release states must match, and all keys/buttons must finish released.
Send complete clicks, drags and chords in ONE call. Windows 1.01 cooperative
USER tracking can otherwise block the agent waiting for an up event that cannot
arrive. Menu/modal interactions spanning calls may still block; timeout is NOT
proof of rollback. This is Windows 1.01 journal playback, not later Win16 ABI
compatibility. Host screenshots observe pixels; no host keyboard/mouse is used.
