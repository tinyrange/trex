"""Bounded semantic MSXML DOM interfaces backed by `binary.xml`."""

load(":facts.star", "guid")

_S_OK = 0
_E_POINTER = 0x80004003
_E_NOINTERFACE = 0x80004002
_E_NOTIMPL = 0x80004001
_E_INVALIDARG = 0x80070057

_CLASSES = [
    "{2933BF90-7B36-11D2-B20E-00C04F983E60}",
]

_INTERFACES = {
    "{00000000-0000-0000-C000-000000000046}": True,
    "{00020400-0000-0000-C000-000000000046}": True,
    "{2933BF80-7B36-11D2-B20E-00C04F983E60}": True,
    "{2933BF81-7B36-11D2-B20E-00C04F983E60}": True,
}

def _write_variant_bstr(machine, address, value):
    data = binary.builder(capacity = 16)
    data.u16le(8)
    data.reserve(6)
    data.u32le(_bstr(machine, value))
    data.u32le(0)
    machine.write(address, data.bytes())

def _guid(machine, address):
    return guid(machine.read(address, 16)) if address else ""

def _bstr(machine, value):
    encoded = binary.encode(value, encoding = "utf16le", nul = True)
    data = binary.builder(capacity = len(encoded) + 4)
    data.u32le(len(encoded) - 2)
    data.append(encoded)
    return machine.allocate(value = data.bytes(), name = "MSXML BSTR") + 4

def _invoke_interface(machine, interface, slot, arguments):
    vtable = machine.read_u32le(interface)
    target = machine.read_u32le(vtable + slot * 4)
    return machine.invoke(target, args = [interface] + arguments)

def _node_name(node):
    return node["name"] if type(node) == "dict" else node.name

def _node_text(node):
    return node["text"] if type(node) == "dict" else node.text

def _node_children(node):
    return node["children"] if type(node) == "dict" else node.children

def _node_attributes(node):
    return node["attributes"] if type(node) == "dict" else node.attributes

def _node_kind(node):
    return node["kind"] if type(node) == "dict" else 1

def _signed(value, bits):
    sign = 1 << (bits - 1)
    mask = (1 << bits) - 1
    value &= mask
    return value - (1 << bits) if value & sign else value

def _variant_text(machine, args):
    kind = args[0] & 0xffff
    if kind == 8 and args[2]:
        return machine.read_cstring(args[2], encoding = "utf16le")
    if kind == 2:
        return str(_signed(args[2], 16))
    if kind == 3:
        return str(_signed(args[2], 32))
    if kind == 5:
        data = binary.builder(capacity = 8)
        data.u32le(args[2])
        data.u32le(args[3])
        return str(binary.read_f64le(data.bytes()))
    if kind == 11:
        return "true" if args[2] & 0xffff else "false"
    if kind == 16:
        return str(_signed(args[2], 8))
    if kind == 17:
        return str(args[2] & 0xff)
    if kind == 18:
        return str(args[2] & 0xffff)
    if kind == 19:
        return str(args[2] & 0xffffffff)
    return None

def _xml_escape(value, attribute = False):
    value = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return value.replace("\"", "&quot;") if attribute else value

def _serialize_node(node):
    kind = _node_kind(node)
    name = _node_name(node)
    text = _node_text(node)
    if kind == 7:
        return "<?" + name + (" " + text if text else "") + "?>"
    attributes = ""
    for attribute in _node_attributes(node):
        attributes += " {}=\"{}\"".format(attribute["name"], _xml_escape(attribute["value"], attribute = True))
    children = _node_children(node)
    if not children and not text:
        return "<" + name + attributes + "/>"
    body = _xml_escape(text)
    for child in children:
        body += _serialize_node(child)
    return "<" + name + attributes + ">" + body + "</" + name + ">"

def _first_descendant(node, name):
    if name == "*" or _node_name(node) == name:
        return node
    for child in _node_children(node):
        found = _first_descendant(child, name)
        if found != None:
            return found
    return None

def _select_single(node, query):
    """Selects the first element for the bounded path subset used by setup."""
    query = query.strip()
    if query == "":
        return None
    descendant = query.startswith("//")
    parts = [part for part in query.split("/") if part != "" and part != "."]
    if not parts:
        return None
    if descendant:
        current = _first_descendant(node, parts[0])
        parts = parts[1:]
    else:
        current = node
        if parts[0] == _node_name(current) or parts[0] == "*":
            parts = parts[1:]
    for part in parts:
        if current == None or part == ".." or part.startswith("@") or "[" in part:
            return None
        selected = None
        for child in _node_children(current):
            if part == "*" or _node_name(child) == part:
                selected = child
                break
        current = selected
    return current

def msxml_dom_provider(kernel = None):
    """Returns a pluggable COM provider for MSXML DOM document classes."""
    state = {"actions": [], "next_object": 1}

    def activate(event, activation, output):
        machine = event.machine
        requested = activation["interface"]
        if not output:
            return _E_POINTER
        machine.write_u32le(output, 0)
        if requested not in _INTERFACES:
            return _E_NOINTERFACE
        identifier = state["next_object"]
        state["next_object"] += 1
        instance = {"async": False, "document": None, "onreadystatechange": 0, "references": 1, "created_children": []}
        interface_address = {"value": 0}
        next_node = {"value": 1}
        nodes_by_interface = {}
        attributes_by_interface = {}

        def attribute_interface(machine, attribute):
            attribute_identifier = next_node["value"]
            next_node["value"] += 1
            address = {"value": 0}
            references = {"value": 1}

            def query_attribute(event):
                if not event.args[2]:
                    return _E_POINTER
                requested = _guid(event.machine, event.args[1])
                event.machine.write_u32le(event.args[2], address["value"])
                references["value"] += 1
                state["actions"].append({
                    "object": identifier,
                    "attribute": attribute["name"],
                    "method": "QueryInterface",
                    "interface": requested,
                })
                return _S_OK

            def add_attribute_reference(event):
                references["value"] += 1
                return references["value"]

            def release_attribute(event):
                references["value"] = max(0, references["value"] - 1)
                return references["value"]

            def attribute_unimplemented(slot):
                def method(event):
                    state["actions"].append({
                        "object": identifier,
                        "attribute": attribute["name"],
                        "method": "attribute.slot" + str(slot),
                        "args": list(event.args[1:]),
                    })
                    return _E_NOTIMPL
                return method

            def get_attribute_name(event):
                if not event.args[1]:
                    return _E_POINTER
                event.machine.write_u32le(event.args[1], _bstr(event.machine, attribute["name"]))
                return _S_OK

            def get_attribute_value(event):
                if not event.args[1]:
                    return _E_POINTER
                _write_variant_bstr(event.machine, event.args[1], attribute["value"])
                state["actions"].append({
                    "object": identifier,
                    "attribute": attribute["name"],
                    "method": "get_nodeValue",
                    "value": attribute["value"],
                })
                return _S_OK

            def put_attribute_value(event):
                variant_type = event.args[1] & 0xffff
                state["actions"].append({
                    "object": identifier,
                    "attribute": attribute["name"],
                    "method": "put_value",
                    "variant_type": variant_type,
                    "args": list(event.args[1:]),
                })
                value = _variant_text(event.machine, event.args[1:5])
                if value == None:
                    return _E_INVALIDARG
                attribute["value"] = value
                state["actions"][-1]["value"] = attribute["value"]
                return _S_OK

            def get_attribute_type(event):
                if not event.args[1]:
                    return _E_POINTER
                event.machine.write_u32le(event.args[1], 2)
                return _S_OK

            def get_attribute_text(event):
                if not event.args[1]:
                    return _E_POINTER
                event.machine.write_u32le(event.args[1], _bstr(event.machine, attribute["value"]))
                return _S_OK

            def get_attribute_specified(event):
                if not event.args[1]:
                    return _E_POINTER
                event.machine.write_u16le(event.args[1], 0xffff)
                return _S_OK

            implemented_attributes = {
                7: get_attribute_name,
                8: get_attribute_value,
                10: get_attribute_type,
                26: get_attribute_text,
                28: get_attribute_specified,
                41: get_attribute_name,
                43: get_attribute_name,
                44: get_attribute_value,
                45: put_attribute_value,
            }
            node_argument_counts = [
                2, 4, 6, 9,
                2, 2, 5, 2, 2, 2, 2, 2, 2, 2, 2,
                7, 4, 3, 3, 2, 2, 3, 2, 2, 2, 2, 2, 2, 5, 2, 2,
                2, 2, 3, 3, 2, 2, 2, 2, 6,
                2, 2, 5,
            ]
            methods = [
                ("QueryInterface", query_attribute, 3),
                ("AddRef", add_attribute_reference, 1),
                ("Release", release_attribute, 1),
            ]
            for slot in range(3, 46):
                methods.append(("slot" + str(slot), implemented_attributes.get(slot, attribute_unimplemented(slot)), node_argument_counts[slot - 3]))
            vtable = binary.builder(capacity = len(methods) * 4)
            for name, callback, argc in methods:
                vtable.u32le(machine.provide_export(
                    callback,
                    module = "trex.msxml",
                    name = "attribute_" + name + "_" + str(identifier) + "_" + str(attribute_identifier),
                    argc = argc,
                ))
            table = machine.allocate(value = vtable.bytes(), name = "IXMLDOMAttribute.vtable")
            value = binary.builder(capacity = 4)
            value.u32le(table)
            address["value"] = machine.allocate(value = value.bytes(), name = "IXMLDOMAttribute " + attribute["name"])
            attributes_by_interface[address["value"]] = attribute
            return address["value"]

        def named_node_map(machine, node):
            map_identifier = next_node["value"]
            next_node["value"] += 1
            address = {"value": 0}
            references = {"value": 1}
            attributes = _node_attributes(node)

            def query_map(event):
                if not event.args[2]:
                    return _E_POINTER
                event.machine.write_u32le(event.args[2], address["value"])
                references["value"] += 1
                return _S_OK

            def add_map_reference(event):
                references["value"] += 1
                return references["value"]

            def release_map(event):
                references["value"] = max(0, references["value"] - 1)
                return references["value"]

            def map_unimplemented(event):
                return _E_NOTIMPL

            def get_named_item(event):
                if not event.args[2]:
                    return _E_POINTER
                event.machine.write_u32le(event.args[2], 0)
                name = event.machine.read_cstring(event.args[1], encoding = "utf16le") if event.args[1] else ""
                selected = None
                for attribute in attributes:
                    if attribute["name"] == name:
                        selected = attribute
                        break
                if selected != None:
                    event.machine.write_u32le(event.args[2], attribute_interface(event.machine, selected))
                state["actions"].append({
                    "object": identifier,
                    "node": _node_name(node),
                    "method": "attributes.getNamedItem",
                    "name": name,
                    "found": selected != None,
                })
                return _S_OK if selected != None else 1  # S_FALSE

            def get_item(event):
                if not event.args[2]:
                    return _E_POINTER
                event.machine.write_u32le(event.args[2], 0)
                index = event.args[1]
                if index < len(attributes):
                    event.machine.write_u32le(event.args[2], attribute_interface(event.machine, attributes[index]))
                return _S_OK

            def set_named_item(event):
                if event.args[2]:
                    event.machine.write_u32le(event.args[2], 0)
                attribute = attributes_by_interface.get(event.args[1])
                if attribute == None:
                    return _E_INVALIDARG
                replaced = -1
                for index in range(len(attributes)):
                    if attributes[index]["name"] == attribute["name"] and attributes[index]["namespace"] == attribute["namespace"]:
                        replaced = index
                        break
                if replaced >= 0:
                    attributes[replaced] = attribute
                else:
                    attributes.append(attribute)
                state["actions"].append({
                    "object": identifier,
                    "node": _node_name(node),
                    "method": "attributes.setNamedItem",
                    "name": attribute["name"],
                    "value": attribute["value"],
                })
                return _S_OK

            def get_length(event):
                if not event.args[1]:
                    return _E_POINTER
                event.machine.write_u32le(event.args[1], len(attributes))
                return _S_OK

            methods = [
                ("QueryInterface", query_map, 3),
                ("AddRef", add_map_reference, 1),
                ("Release", release_map, 1),
                ("GetTypeInfoCount", map_unimplemented, 2),
                ("GetTypeInfo", map_unimplemented, 4),
                ("GetIDsOfNames", map_unimplemented, 6),
                ("Invoke", map_unimplemented, 9),
                ("getNamedItem", get_named_item, 3),
                ("setNamedItem", set_named_item, 3),
                ("removeNamedItem", map_unimplemented, 3),
                ("get_item", get_item, 3),
                ("get_length", get_length, 2),
                ("getQualifiedItem", map_unimplemented, 4),
                ("removeQualifiedItem", map_unimplemented, 4),
                ("nextNode", map_unimplemented, 2),
                ("reset", map_unimplemented, 1),
                ("get__newEnum", map_unimplemented, 2),
            ]
            vtable = binary.builder(capacity = len(methods) * 4)
            for name, callback, argc in methods:
                vtable.u32le(machine.provide_export(
                    callback,
                    module = "trex.msxml",
                    name = "attributes_" + name + "_" + str(identifier) + "_" + str(map_identifier),
                    argc = argc,
                ))
            table = machine.allocate(value = vtable.bytes(), name = "IXMLDOMNamedNodeMap.vtable")
            value = binary.builder(capacity = 4)
            value.u32le(table)
            address["value"] = machine.allocate(value = value.bytes(), name = "IXMLDOMNamedNodeMap " + _node_name(node))
            return address["value"]

        def node_interface(machine, node):
            node_identifier = next_node["value"]
            next_node["value"] += 1
            node_address = {"value": 0}
            references = {"value": 1}

            def query_node_interface(event):
                if not event.args[2]:
                    return _E_POINTER
                event.machine.write_u32le(event.args[2], 0)
                requested = _guid(event.machine, event.args[1])
                if requested not in _INTERFACES:
                    return _E_NOINTERFACE
                references["value"] += 1
                event.machine.write_u32le(event.args[2], node_address["value"])
                return _S_OK

            def add_node_reference(event):
                references["value"] += 1
                return references["value"]

            def release_node(event):
                references["value"] = max(0, references["value"] - 1)
                return references["value"]

            def node_unimplemented(slot):
                def method(event):
                    state["actions"].append({
                        "object": identifier,
                        "node": _node_name(node),
                        "method": "node.slot" + str(slot),
                        "args": list(event.args[1:]),
                    })
                    return _E_NOTIMPL
                return method

            def get_node_name(event):
                if not event.args[1]:
                    return _E_POINTER
                event.machine.write_u32le(event.args[1], _bstr(event.machine, _node_name(node)))
                state["actions"].append({"object": identifier, "node": _node_name(node), "method": "get_nodeName"})
                return _S_OK

            def get_node_type(event):
                if not event.args[1]:
                    return _E_POINTER
                event.machine.write_u32le(event.args[1], _node_kind(node))
                return _S_OK

            def get_text(event):
                if not event.args[1]:
                    return _E_POINTER
                event.machine.write_u32le(event.args[1], _bstr(event.machine, _node_text(node)))
                state["actions"].append({"object": identifier, "node": _node_name(node), "method": "get_text", "value": _node_text(node)})
                return _S_OK

            def get_attributes(event):
                if not event.args[1]:
                    return _E_POINTER
                event.machine.write_u32le(event.args[1], named_node_map(event.machine, node))
                state["actions"].append({"object": identifier, "node": _node_name(node), "method": "get_attributes"})
                return _S_OK

            def append_node(event):
                if not event.args[2]:
                    return _E_POINTER
                event.machine.write_u32le(event.args[2], 0)
                child = nodes_by_interface.get(event.args[1])
                if child == None or type(node) != "dict":
                    return _E_INVALIDARG
                node["children"].append(child)
                event.machine.write_u32le(event.args[2], event.args[1])
                _invoke_interface(event.machine, event.args[1], 1, [])
                return _S_OK

            def get_owner_document(event):
                if not event.args[1]:
                    return _E_POINTER
                event.machine.write_u32le(event.args[1], interface_address["value"])
                instance["references"] += 1
                return _S_OK

            def select_node(event):
                query = event.machine.read_cstring(event.args[1], encoding = "utf16le") if event.args[1] else ""
                if not event.args[2]:
                    return _E_POINTER
                event.machine.write_u32le(event.args[2], 0)
                selected = _select_single(node, query)
                if selected != None:
                    event.machine.write_u32le(event.args[2], node_interface(event.machine, selected))
                state["actions"].append({
                    "object": identifier,
                    "node": _node_name(node),
                    "method": "selectSingleNode",
                    "query": query,
                    "found": _node_name(selected) if selected != None else "",
                })
                return _S_OK

            implemented_nodes = {
                7: get_node_name,
                10: get_node_type,
                17: get_attributes,
                21: append_node,
                23: get_owner_document,
                26: get_text,
                37: select_node,
            }
            node_argument_counts = [
                2, 4, 6, 9,
                2, 2, 5, 2, 2, 2, 2, 2, 2, 2, 2,
                7, 4, 3, 3, 2, 2, 3, 2, 2, 2, 2, 2, 2, 5, 2, 2,
                2, 2, 3, 3, 2, 2, 2, 2, 6,
            ]
            methods = [
                ("QueryInterface", query_node_interface, 3),
                ("AddRef", add_node_reference, 1),
                ("Release", release_node, 1),
            ]
            for slot in range(3, 43):
                methods.append(("slot" + str(slot), implemented_nodes.get(slot, node_unimplemented(slot)), node_argument_counts[slot - 3]))
            vtable = binary.builder(capacity = len(methods) * 4)
            for name, callback, argc in methods:
                vtable.u32le(machine.provide_export(
                    callback,
                    module = "trex.msxml",
                    name = "node_" + name + "_" + str(identifier) + "_" + str(node_identifier),
                    argc = argc,
                ))
            table = machine.allocate(value = vtable.bytes(), name = "IXMLDOMNode.vtable")
            value = binary.builder(capacity = 4)
            value.u32le(table)
            node_address["value"] = machine.allocate(value = value.bytes(), name = "IXMLDOMNode " + _node_name(node))
            nodes_by_interface[node_address["value"]] = node
            return node_address["value"]

        def query_interface(event):
            if not event.args[2]:
                return _E_POINTER
            event.machine.write_u32le(event.args[2], 0)
            requested = _guid(event.machine, event.args[1])
            state["actions"].append({"object": identifier, "method": "QueryInterface", "interface": requested})
            if requested not in _INTERFACES:
                return _E_NOINTERFACE
            instance["references"] += 1
            event.machine.write_u32le(event.args[2], interface_address["value"])
            return _S_OK

        def add_ref(event):
            instance["references"] += 1
            return instance["references"]

        def release(event):
            instance["references"] = max(0, instance["references"] - 1)
            return instance["references"]

        def unimplemented(slot):
            def method(event):
                state["actions"].append({
                    "object": identifier,
                    "method": "slot" + str(slot),
                    "args": list(event.args[1:]),
                })
                return _E_NOTIMPL
            return method

        def put_async(event):
            instance["async"] = event.args[1] != 0
            state["actions"].append({
                "object": identifier,
                "method": "put_async",
                "value": instance["async"],
            })
            return _S_OK

        def put_event_handler(event):
            variant_type = event.args[1] & 0xffff
            handler = event.args[3] if variant_type in [9, 13] else 0
            previous = instance["onreadystatechange"]
            if previous:
                _invoke_interface(event.machine, previous, 2, [])
            instance["onreadystatechange"] = handler
            if handler:
                _invoke_interface(event.machine, handler, 1, [])
            state["actions"].append({
                "object": identifier,
                "method": "put_onreadystatechange",
                "variant_type": variant_type,
                "handler": handler,
            })
            return _S_OK

        def get_ready_state(event):
            if not event.args[1]:
                return _E_POINTER
            event.machine.write_u32le(event.args[1], 4)
            state["actions"].append({
                "object": identifier,
                "method": "get_readyState",
                "value": 4,
            })
            return _S_OK

        def parse_error(machine):
            parse_interface = {"value": 0}

            def query_parse_interface(event):
                if not event.args[2]:
                    return _E_POINTER
                event.machine.write_u32le(event.args[2], parse_interface["value"])
                return _S_OK

            def parse_reference(event):
                return 1

            def dispatch_unimplemented(event):
                return _E_NOTIMPL

            def numeric_value(name):
                def method(event):
                    if not event.args[1]:
                        return _E_POINTER
                    event.machine.write_u32le(event.args[1], 0)
                    state["actions"].append({"object": identifier, "method": "parseError." + name, "value": 0})
                    return _S_OK
                return method

            def string_value(name):
                def method(event):
                    if not event.args[1]:
                        return _E_POINTER
                    event.machine.write_u32le(event.args[1], _bstr(event.machine, ""))
                    state["actions"].append({"object": identifier, "method": "parseError." + name, "value": ""})
                    return _S_OK
                return method

            methods = [
                ("QueryInterface", query_parse_interface, 3),
                ("AddRef", parse_reference, 1),
                ("Release", parse_reference, 1),
                ("GetTypeInfoCount", dispatch_unimplemented, 2),
                ("GetTypeInfo", dispatch_unimplemented, 4),
                ("GetIDsOfNames", dispatch_unimplemented, 6),
                ("Invoke", dispatch_unimplemented, 9),
                ("get_errorCode", numeric_value("errorCode"), 2),
                ("get_url", string_value("url"), 2),
                ("get_reason", string_value("reason"), 2),
                ("get_srcText", string_value("srcText"), 2),
                ("get_line", numeric_value("line"), 2),
                ("get_linepos", numeric_value("linepos"), 2),
                ("get_filepos", numeric_value("filepos"), 2),
            ]
            vtable = binary.builder(capacity = len(methods) * 4)
            for name, callback, argc in methods:
                vtable.u32le(machine.provide_export(
                    callback,
                    module = "trex.msxml",
                    name = "parse_" + name + "_" + str(identifier),
                    argc = argc,
                ))
            table = machine.allocate(value = vtable.bytes(), name = "IXMLDOMParseError.vtable")
            value = binary.builder(capacity = 4)
            value.u32le(table)
            parse_interface["value"] = machine.allocate(value = value.bytes(), name = "IXMLDOMParseError")
            return parse_interface["value"]

        def get_parse_error(event):
            if not event.args[1]:
                return _E_POINTER
            value = parse_error(event.machine)
            event.machine.write_u32le(event.args[1], value)
            state["actions"].append({"object": identifier, "method": "get_parseError"})
            return _S_OK

        def select_single_node(event):
            query = event.machine.read_cstring(event.args[1], encoding = "utf16le") if event.args[1] else ""
            if event.args[2]:
                event.machine.write_u32le(event.args[2], 0)
            root = instance["document"].root if instance["document"] != None else None
            selected = _select_single(root, query) if root != None else None
            if selected != None and event.args[2]:
                event.machine.write_u32le(event.args[2], node_interface(event.machine, selected))
            state["actions"].append({
                "object": identifier,
                "method": "selectSingleNode",
                "query": query,
                "found": _node_name(selected) if selected != None else "",
            })
            return _S_OK

        def append_document_child(event):
            if not event.args[2]:
                return _E_POINTER
            event.machine.write_u32le(event.args[2], 0)
            child = nodes_by_interface.get(event.args[1])
            if child == None:
                return _E_INVALIDARG
            instance["created_children"].append(child)
            event.machine.write_u32le(event.args[2], event.args[1])
            _invoke_interface(event.machine, event.args[1], 1, [])
            state["actions"].append({
                "object": identifier,
                "method": "appendChild",
                "child": _node_name(child),
                "kind": _node_kind(child),
            })
            return _S_OK

        def create_processing_instruction(event):
            if not event.args[3]:
                return _E_POINTER
            target = event.machine.read_cstring(event.args[1], encoding = "utf16le") if event.args[1] else ""
            data = event.machine.read_cstring(event.args[2], encoding = "utf16le") if event.args[2] else ""
            node = {"name": target, "text": data, "kind": 7, "attributes": [], "children": []}
            event.machine.write_u32le(event.args[3], node_interface(event.machine, node))
            state["actions"].append({
                "object": identifier,
                "method": "createProcessingInstruction",
                "target": target,
                "data": data,
            })
            return _S_OK

        def create_element(event):
            if not event.args[2]:
                return _E_POINTER
            name = event.machine.read_cstring(event.args[1], encoding = "utf16le") if event.args[1] else ""
            node = {"name": name, "text": "", "kind": 1, "attributes": [], "children": []}
            event.machine.write_u32le(event.args[2], node_interface(event.machine, node))
            state["actions"].append({
                "object": identifier,
                "method": "createElement",
                "name": name,
            })
            return _S_OK

        def create_attribute(event):
            if not event.args[2]:
                return _E_POINTER
            name = event.machine.read_cstring(event.args[1], encoding = "utf16le") if event.args[1] else ""
            attribute = {"name": name, "namespace": "", "value": ""}
            event.machine.write_u32le(event.args[2], attribute_interface(event.machine, attribute))
            state["actions"].append({
                "object": identifier,
                "method": "createAttribute",
                "name": name,
                "return": event.return_address,
            })
            return _S_OK

        def save_document(event):
            variant_type = event.args[1] & 0xffff
            if variant_type != 8 or not event.args[3] or kernel == None:
                return _E_INVALIDARG
            target = event.machine.read_cstring(event.args[3], encoding = "utf16le")
            path = target.replace("/", "\\")
            while "\\\\" in path:
                path = path.replace("\\\\", "\\")
            path = path.rstrip("\\").lower()
            text = ""
            for child in instance["created_children"]:
                text += _serialize_node(child) + "\r\n"
            encoded = binary.encode(text, encoding = "utf16le")
            output = binary.builder(capacity = len(encoded) + 2)
            output.append(b"\xff\xfe")
            output.append(encoded)
            data = output.bytes()
            kernel.state["paths"][path] = {
                "directory": False,
                "data": data,
                "size": len(data),
                "dirty": True,
            }
            state["actions"].append({
                "object": identifier,
                "method": "save",
                "path": target,
                "size": len(data),
            })
            return _S_OK

        def abort(event):
            state["actions"].append({"object": identifier, "method": "abort"})
            return _S_OK

        def load_document(event):
            machine = event.machine
            success = event.args[5]
            if success:
                machine.write_u16le(success, 0)
            variant_type = event.args[1] & 0xffff
            stream = event.args[3]
            action = {
                "object": identifier,
                "method": "load",
                "variant_type": variant_type,
                "stream": stream,
            }
            state["actions"].append(action)
            if variant_type in [9, 13] and stream:
                statistics = machine.allocate(size = 72, name = "MSXML IStream STATSTG")
                result = _invoke_interface(machine, stream, 12, [statistics, 1])
                if result.reason != "return" or result.value >= 0x80000000:
                    action["result"] = "stat-failed"
                    return result.value if result.reason == "return" else 0x80004005
                size = machine.read_u64le(statistics + 8)
                if size > 16 << 20:
                    action["result"] = "stream-too-large"
                    return _E_INVALIDARG
                result = _invoke_interface(machine, stream, 5, [0, 0, 0, 0])
                if result.reason != "return" or result.value >= 0x80000000:
                    action["result"] = "seek-failed"
                    return result.value if result.reason == "return" else 0x80004005
                buffer = machine.allocate(size = max(1, size), name = "MSXML input")
                count = machine.allocate(size = 4, name = "MSXML input count")
                result = _invoke_interface(machine, stream, 3, [buffer, size, count])
                if result.reason != "return" or result.value >= 0x80000000:
                    action["result"] = "read-failed"
                    return result.value if result.reason == "return" else 0x80004005
                read = machine.read_u32le(count)
                if read != size:
                    action["result"] = "short-read"
                    return 1
                data = machine.read(buffer, read)
            elif variant_type == 8 and stream:
                source = machine.read_cstring(stream, encoding = "utf16le")
                action["source"] = source
                if source.lstrip().startswith("<"):
                    data = binary.encode(source)
                elif kernel != None:
                    path = source.replace("/", "\\")
                    while "\\\\" in path:
                        path = path.replace("\\\\", "\\")
                    entry = kernel.state["paths"].get(path.rstrip("\\").lower())
                    if entry == None or entry.get("directory", False):
                        action["result"] = "file-not-found"
                        return _E_INVALIDARG
                    data = kernel.state["file_data"](path.rstrip("\\").lower())
                else:
                    action["result"] = "file-source-unavailable"
                    return _E_INVALIDARG
            else:
                action["result"] = "unsupported-source"
                return _E_INVALIDARG
            instance["document"] = binary.xml(data)
            machine.write_u16le(success, 0xffff)
            action["result"] = "loaded"
            action["size"] = len(data)
            handler = instance["onreadystatechange"]
            if instance["async"] and handler:
                null_guid = machine.allocate(size = 16, name = "MSXML null IID")
                parameters = machine.allocate(size = 16, name = "MSXML DISPPARAMS")
                invoked = _invoke_interface(machine, handler, 6, [0, null_guid, 0, 1, parameters, 0, 0, 0])
                action["callback_reason"] = invoked.reason
                action["callback_result"] = invoked.value
            return _S_OK

        implemented = {
            21: append_document_child,
            47: create_element,
            52: create_processing_instruction,
            53: create_attribute,
            58: load_document,
            59: get_ready_state,
            60: get_parse_error,
            63: put_async,
            64: abort,
            66: save_document,
            73: put_event_handler,
            37: select_single_node,
        }
        methods = [
            ("QueryInterface", query_interface, 3),
            ("AddRef", add_ref, 1),
            ("Release", release, 1),
        ]
        # IDispatch, IXMLDOMNode, and IXMLDOMDocument use stdcall, so each
        # modeled slot carries its real stack width even before its semantics
        # are needed. This lets an unsupported call fail without corrupting
        # the caller's stack.
        argument_counts = [
            2, 4, 6, 9,
            2, 2, 5, 2, 2, 2, 2, 2, 2, 2, 2,
            7, 4, 3, 3, 2, 2, 3, 2, 2, 2, 2, 2, 2, 5, 2, 2,
            2, 2, 3, 3, 2, 2, 2, 2, 6,
            2, 2, 2, 2, 3, 2, 3, 3, 3, 4, 3, 3, 3, 8, 3, 6,
            2, 2, 2, 2, 2, 1, 3, 5, 2, 2, 2, 2, 2, 2, 5, 5, 5,
        ]
        for slot in range(3, 76):
            methods.append(("slot" + str(slot), implemented.get(slot, unimplemented(slot)), argument_counts[slot - 3]))
        vtable = binary.builder(capacity = len(methods) * 4)
        for name, callback, argc in methods:
            vtable.u32le(machine.provide_export(
                callback,
                module = "trex.msxml",
                name = name + "_" + str(identifier),
                argc = argc,
            ))
        vtable_address = machine.allocate(value = vtable.bytes(), name = "IXMLDOMDocument.vtable")
        value = binary.builder(capacity = 4)
        value.u32le(vtable_address)
        interface = machine.allocate(value = value.bytes(), name = "IXMLDOMDocument")
        interface_address["value"] = interface
        machine.write_u32le(output, interface)
        state["actions"].append({
            "object": identifier,
            "method": "activate",
            "class": activation["class"],
            "interface": requested,
        })
        return _S_OK

    return {"classes": _CLASSES, "activate": activate, "state": state}
