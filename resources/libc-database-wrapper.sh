#!/bin/bash
# libc-database CLI shim: the hexstrike endpoint cds into /opt/libc-database
# and runs ./find / ./dump / ./download.
exec /opt/libc-database/find "$@"
