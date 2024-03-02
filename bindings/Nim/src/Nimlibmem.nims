switch("define", "nodeclguards")
switch("define", "futharkRebuild")
switch("define", "opirRebuild")
--app:lib
switch("tlsEmulation", "off")
switch("verbosity", "2")
switch("define", "echoForwards")
switch("x")
switch("out", "src/nimlibmem.dll")
--docInternal
--experimental:compiletimeFFI
--backend:c
--clib:"src/libmem_partial"
--debuginfo:on
--project
--d:release