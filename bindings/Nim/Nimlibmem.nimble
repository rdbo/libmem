# Package

version       = "0.1.0"
author        = "Hypnootika"
description   = "A new awesome nimble package"
license       = "MIT"
srcDir        = "src"
binDir        = "release"
bin           = @["nimlibmem"]
# Dependencies

requires "nim >= 2.0.0, winim, futhark"
