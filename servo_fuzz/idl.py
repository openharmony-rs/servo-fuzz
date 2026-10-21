"""Extracts a model of Servo's WebIDL (interfaces, members, argument types) for the `idl` generator.

The model is plain JSON, written once per Servo checkout: `python -m servo_fuzz idl-model`.
"""

import json
import os
import re
import sys
import tempfile
from pathlib import Path

CONDITIONAL_START = re.compile(r"\s*// skip-unless ([A-Z_]+) begin\n")
CONDITIONAL_END = re.compile(r"\s*// skip-unless ([A-Z_]+) end\n")


def _type(t) -> dict:
    """A JSON description of an IDL type."""
    nullable = t.nullable()
    if nullable:
        t = t.inner
    if t.isUnion():
        result = {"k": "union", "of": [_type(m) for m in t.flatMemberTypes]}
    elif t.isSequence() or (hasattr(t, "isObservableArray") and t.isObservableArray()):
        result = {"k": "sequence", "of": _type(t.inner)}
    elif t.isRecord():
        result = {"k": "record", "of": _type(t.inner)}
    elif t.isPromise():
        result = {"k": "promise"}
    elif t.isEnum():
        result = {"k": "enum", "values": list(t.inner.values())}
    elif t.isDictionary():
        result = {"k": "dictionary", "name": t.inner.identifier.name}
    elif t.isCallback() or t.isCallbackInterface():
        result = {"k": "callback"}
    elif t.isBufferSource() if hasattr(t, "isBufferSource") else False:
        result = {"k": "buffer"}
    elif t.isSpiderMonkeyInterface():
        result = {"k": "buffer", "name": t.name}
    elif t.isInterface():
        result = {"k": "interface", "name": t.inner.identifier.name}
    elif t.isString():
        result = {"k": "string"}
    elif t.isBoolean():
        result = {"k": "boolean"}
    elif t.isPrimitive():
        result = {"k": "number", "name": t.name}
    elif t.isAny():
        result = {"k": "any"}
    elif t.isObject():
        result = {"k": "object"}
    elif t.isUndefined():
        result = {"k": "undefined"}
    else:
        result = {"k": "any", "unknown": str(t)}
    if nullable:
        result["nullable"] = True
    return result


def _arguments(arguments) -> list[dict]:
    return [
        {"name": a.identifier.name, "type": _type(a.type), "optional": a.optional, "variadic": a.variadic}
        for a in arguments
    ]


def _pref(node) -> str | None:
    pref = node.getExtendedAttribute("Pref")
    return pref[0] if pref else None


def build_model(servo_dir: Path) -> dict:
    bindings = servo_dir / "components/script_bindings"
    sys.path.insert(0, str(bindings / "third_party/WebIDL/parser"))
    sys.path.insert(0, str(bindings / "third_party/ply"))
    import WebIDL

    parser = WebIDL.Parser(tempfile.mkdtemp(prefix="servo-fuzz-webidl-"))
    for path in sorted((bindings / "webidls").glob("*.webidl")):
        contents = path.read_text(encoding="utf-8")
        lines, enabled = [], [True]
        for line in contents.splitlines(keepends=True):
            if CONDITIONAL_START.fullmatch(line):
                enabled.append(enabled[-1])
            elif CONDITIONAL_END.fullmatch(line):
                enabled.pop()
            elif enabled[-1]:
                lines.append(line)
        parser.parse("".join(lines), str(path))
    results = parser.finish()

    interfaces, dictionaries, callbacks = {}, {}, set()
    for node in results:
        if isinstance(node, WebIDL.IDLDictionary):
            members = []
            d = node
            while d:
                members += [
                    {"name": m.identifier.name, "type": _type(m.type), "required": not m.optional} for m in d.members
                ]
                d = d.parent
            dictionaries[node.identifier.name] = members
        elif isinstance(node, (WebIDL.IDLInterface, WebIDL.IDLNamespace)) and not node.isCallback():
            if "Window" not in node.exposureSet:
                continue
            entry = {
                "parent": node.parent.identifier.name if getattr(node, "parent", None) else None,
                "namespace": node.isNamespace(),
                "pref": _pref(node),
                "constructors": [],
                "methods": [],
                "attributes": [],
                "statics": [],
            }
            ctor = node.ctor() if hasattr(node, "ctor") else None
            if ctor and not node.isNamespace():
                entry["constructors"] = [_arguments(args) for _, args in ctor.signatures()]
            for member in node.members:
                if not ("Window" in member.exposureSet):
                    continue
                if member.isMethod() and member.identifier.name and not member.isLegacycaller():
                    if member.isStringifier() and not member.identifier.name:
                        continue
                    for return_type, args in member.signatures():
                        item = {
                            "name": member.identifier.name,
                            "args": _arguments(args),
                            "returns": _type(return_type),
                            "pref": _pref(member),
                        }
                        (entry["statics"] if member.isStatic() or node.isNamespace() else entry["methods"]).append(item)
                elif member.isAttr():
                    item = {
                        "name": member.identifier.name,
                        "type": _type(member.type),
                        "readonly": member.readonly,
                        "pref": _pref(member),
                    }
                    if member.isStatic():
                        continue
                    entry["attributes"].append(item)
            interfaces[node.identifier.name] = entry
    return {"interfaces": interfaces, "dictionaries": dictionaries}


def write_model(servo_dir: Path, out: Path) -> dict:
    model = build_model(servo_dir)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(model, indent=1, sort_keys=True))
    return model
