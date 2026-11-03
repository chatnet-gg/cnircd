#!/usr/bin/env python3
"""Portable replacement for make_test_runtime.sh's old `grep -P` pipeline
(FreeBSD's `grep` has no -P) -- extracts the quoted string items out of
a meson.build `name = [ '...', '...' ]` array literal.

Usage: extract_meson_list.py <meson.build path> <variable name>
"""
import re
import sys

path, varname = sys.argv[1], sys.argv[2]
with open(path) as f:
    text = f.read()

block = re.search(rf"{re.escape(varname)}\s*=\s*\[.*?\]", text, re.DOTALL)
if not block:
    sys.exit(f"extract_meson_list.py: no '{varname} = [...]' block found in {path}")

items = re.findall(r"'([^']+)'", block.group(0))
print(" ".join(items))
