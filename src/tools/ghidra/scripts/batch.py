# @category APRE
# -*- coding: utf-8 -*-
# @runtime Jython
"""Run validated read-only queries inside the same headless invocation."""

from _common import parse_args, emit_result, dispatch, fail

params = parse_args(getScriptArgs())
allowed = set(["inspect.py", "list_functions.py", "list_globals.py", "decompile.py",
               "xrefs_to.py", "xrefs_from.py", "get_strings.py", "read_bytes.py",
               "read_string.py", "get_cfg.py", "get_call_graph.py", "find_crypto.py", "disassemble.py"])
results = []
for operation in params["operations"]:
    if operation["script"] not in allowed:
        fail("batch only supports read-only scripts")
    item = dispatch(globals(), envelope={"script": operation["script"],
                                        "arguments": operation["arguments"]}, emit=False)
    failed = "_error" in item
    for detail in item.get("_diagnostics", []):
        detail["details"].update({"index": operation["index"], "tool_name": operation["tool_name"]})
    results.append({
        "index": operation["index"], "tool_name": operation["tool_name"], "status": item.get("_status", "error") if failed else "ok",
        "error": ("operations[%d] (%s): %s" % (operation["index"], operation["tool_name"], item["_error"])) if failed else None,
        "data": item.get("_data") if failed else dict((k, v) for k, v in item.items() if not k.startswith("_")),
        "limitations": item.get("_limitations", []), "diagnostics": item.get("_diagnostics", []),
    })
emit_result({"results": results, "all_succeeded": all(item["status"] == "ok" for item in results)})
