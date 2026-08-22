#!/bin/bash
# pwntools CLI shim: the hexstrike pwntools endpoint generates a python script
# that does `from pwn import *`, so availability == the module importing cleanly.
exec python3 -c "import pwn, importlib.metadata as m; print('pwntools ' + m.version('pwntools'))"
