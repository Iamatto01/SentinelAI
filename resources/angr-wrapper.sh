#!/bin/bash
# angr CLI shim: the hexstrike angr endpoint generates a python script that
# does `import angr`, so availability == the module importing cleanly.
exec python3 -c "import angr; print('angr ' + angr.__version__)"
