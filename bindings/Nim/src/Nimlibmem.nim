import futhark, os, strutils, winim
proc renameCb(n, k: string, p = ""): string =
  n.replace("LM_", "").replace("lm_", "")

const
  libname = "src/libmem.dll"
importc:
  outputPath "release/nimlibmem.nim"
  path "Libmem"
  renameCallback renameCb
  "libmem.h"

{.passL: "-L. -l:src/libmem.dll".}