#!/usr/bin/env bash
# Run through r_windev ':; bash -s' after copying null-read.cpp to the exact directory.
# This script only writes the explicitly isolated fixture directory.
set -eu
fixture_dir=/d/da/rich-report-canary-20261015
cd "$fixture_dir"
mkdir -p matching mismatched
compiler=$(command -v cl.exe)
debugger=$(command -v cdb.exe)
printf 'Compiler: %s\nDebugger: %s\n' "$compiler" "$debugger" > tool-paths.txt
"$debugger" -version > cdb-version.txt 2>&1
MSYS2_ARG_CONV_EXCL='*' "$compiler" /nologo /Bv /Od /Zi /GS- /EHsc /FC /DCANARY_VARIANT=1 /Fo:matching/null-read.obj /Fd:matching/compiler.pdb /Fe:matching/null-read.exe null-read.cpp /link /NODEFAULTLIB /ENTRY:main /SUBSYSTEM:CONSOLE /MACHINE:X64 /DEBUG:FULL /INCREMENTAL:NO /PDB:matching/null-read.pdb /PDBALTPATH:null-read.pdb > matching/build.log 2>&1
MSYS2_ARG_CONV_EXCL='*' "$compiler" /nologo /Bv /Od /Zi /GS- /EHsc /FC /DCANARY_VARIANT=2 /Fo:mismatched/null-read.obj /Fd:mismatched/compiler.pdb /Fe:mismatched/null-read.exe null-read.cpp /link /NODEFAULTLIB /ENTRY:main /SUBSYSTEM:CONSOLE /MACHINE:X64 /DEBUG:FULL /INCREMENTAL:NO /PDB:mismatched/null-read.pdb /PDBALTPATH:null-read.pdb > mismatched/build.log 2>&1
cat > capture.cdb <<'CDB'
.sympath D:/da/rich-report-canary-20261015/matching
sxe -c ".exr -1;.ecxr;r;kn L0x20;u @rip L0x4;.dump /ma D:/da/rich-report-canary-20261015/null-read.dmp;q" av
g
CDB
MSYS2_ARG_CONV_EXCL='*' "$debugger" -logo D:/da/rich-report-canary-20261015/capture.log -cf D:/da/rich-report-canary-20261015/capture.cdb D:/da/rich-report-canary-20261015/matching/null-read.exe > capture-console.log 2>&1
sha256sum null-read.cpp matching/null-read.exe matching/null-read.pdb mismatched/null-read.exe mismatched/null-read.pdb null-read.dmp > SHA256SUMS
wc -c matching/build.log mismatched/build.log capture.log null-read.dmp
cat SHA256SUMS
