#!/bin/sh
# to_utf8.sh IN OUT - copy IN to OUT as UTF-8 with LF line endings.
# Files written by PowerShell redirection are UTF-16 with a BOM and CRLF,
# which compilers cannot read; plain files are copied unchanged apart from CR.
# IN is never modified.
set -e
in="$1"; out="$2"
if [ "$(head -c 2 "$in" | od -An -tx1 | tr -d ' \n')" = "fffe" ]; then
    iconv -f UTF-16 -t UTF-8 "$in" | tr -d '\r' > "$out"
else
    tr -d '\r' < "$in" > "$out"
fi
