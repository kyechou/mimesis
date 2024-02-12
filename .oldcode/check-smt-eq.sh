#!/bin/bash

set -e
set -o nounset

SCRIPT_DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
cd "$SCRIPT_DIR"

[ $UID -eq 0 ] &&
    (
        echo '[!] Please run this script without root privilege' >&2
        exit 1
    )

[ $# -ne 2 ] &&
    (
        echo "[!] Usage: $0 <smt file 1> <smt file 2>"
        exit 1
    )

Z3='/opt/cxx-common/libraries/z3/bin/z3'
[ -x "$Z3" ] ||
    (
        echo "[-] $Z3 not found" >&2
        exit 1
    )

FILE1="$1"
FILE2="$2"
TESTFILE="temp.smt2"
rm -f "$TESTFILE"

[ "$(head -n1 "$FILE1")" = "(set-logic QF_AUFBV )" ] && [ \
    "$(head -n1 "$FILE2")" = "(set-logic QF_AUFBV )" ] ||
    (
        echo "[-] Unexpected set-logic" >&2
        exit 1
    )

SYM_VARS_1=$(grep -E '\(declare' "$FILE1" | awk '{print $2}')
SYM_VARS_2=$(grep -E '\(declare' "$FILE2" | awk '{print $2}')

[ "${SYM_VARS_1[*]}" = "${SYM_VARS_2[*]}" ] ||
    (
        echo "[-] Different symbolic variables" >&2
        exit 1
    )

SYM_VARS=${SYM_VARS_1}
SYM_PREFIX='EQ__'

sed "$FILE1" -e '/^(check-sat)$/d' -e '/^(exit)$/d' >>"$TESTFILE"

cmd="sed '$FILE2' -e '1d' -e '/^(check-sat)$/d' -e '/^(exit)$/d'"
for SYM_VAR in "${SYM_VARS[@]}"; do
    cmd+=" -e 's/\<${SYM_VAR}\>/${SYM_PREFIX}${SYM_VAR}/g'"
done
eval "$cmd" >>"$TESTFILE"

# TODO
for SYM_VAR in "${SYM_VARS[@]}"; do
    {
        echo "(assert (not (= (select ${SYM_VAR} (_ bv0 32)) (select ${SYM_PREFIX}${SYM_VAR} (_ bv0 32)))))"
        echo "(assert (not (= (select ${SYM_VAR} (_ bv1 32)) (select ${SYM_PREFIX}${SYM_VAR} (_ bv1 32)))))"
        echo "(assert (not (= (select ${SYM_VAR} (_ bv2 32)) (select ${SYM_PREFIX}${SYM_VAR} (_ bv2 32)))))"
        echo "(assert (not (= (select ${SYM_VAR} (_ bv3 32)) (select ${SYM_PREFIX}${SYM_VAR} (_ bv3 32)))))"
    } >>"$TESTFILE"
done

echo '(check-sat)' >>"$TESTFILE"
echo '(exit)' >>"$TESTFILE"

# unsat means the two formulas are equivalent
"$Z3" "$TESTFILE"
rm -f "$TESTFILE"
