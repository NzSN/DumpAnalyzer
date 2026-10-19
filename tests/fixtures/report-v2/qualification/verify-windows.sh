set -eu
fixture_dir=/d/da/rich-report-canary-20261015
cd "$fixture_dir"
cat > verify-matching.cdb <<'CDB'
.sympath D:/da/rich-report-canary-20261015/matching
.srcpath D:/da/rich-report-canary-20261015
.symopt-0x40
.lines -e
.reload /f null-read.exe
.exr -1
.ecxr
r
kn L0x20
u @rip L0x4
lmv m null*
!lmi null_read
ln @rip
q
CDB
cat > verify-mismatched.cdb <<'CDB'
.sympath D:/da/rich-report-canary-20261015/mismatched
.symopt-0x40
!sym noisy
.reload /f null-read.exe
.exr -1
.ecxr
kn L0x20
lmv m null*
!lmi null_read
q
CDB
debugger=$(command -v cdb.exe)
MSYS2_ARG_CONV_EXCL='*' "$debugger" -z D:/da/rich-report-canary-20261015/null-read.dmp -y D:/da/rich-report-canary-20261015/matching -cf D:/da/rich-report-canary-20261015/verify-matching.cdb -logo D:/da/rich-report-canary-20261015/verify-matching.log > verify-matching-console.log 2>&1
MSYS2_ARG_CONV_EXCL='*' "$debugger" -z D:/da/rich-report-canary-20261015/null-read.dmp -y D:/da/rich-report-canary-20261015/mismatched -cf D:/da/rich-report-canary-20261015/verify-mismatched.cdb -logo D:/da/rich-report-canary-20261015/verify-mismatched.log > verify-mismatched-console.log 2>&1
wc -c verify-matching.log verify-mismatched.log
