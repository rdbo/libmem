## This is a test for the functions imported from Libmem.h
import ../release/nimlibmem
import strutils
import winim/winstr

const test_process = "notepad.exe"

## Getprocess tests
var p: processt
var status: boolt = Getprocess(p.addr)
echo status
echo "Process ID: ", p.pid, "\nProcess Name: ", nullTerminated($$p.name), "\nProcess bits: ", p.bits, "\nProcess Start Time: ", p.starttime, "\nProcess Path: ", nullTerminated($$p.path)

## Findprocess tests
var p2: processt
var status2: boolt = Findprocess(test_process, p2.addr)
echo status2
echo "Process ID: ", p2.pid, "\nProcess Name: ", nullTerminated($$p2.name), "\nProcess bits: ", p2.bits, "\nProcess Start Time: ", p2.starttime, "\nProcess Path: ", nullTerminated($$p2.path)

## Getprocessex tests
var p3: processt
var status3: boolt = Getprocessex(p2.pid, p3.addr)
echo status3
echo "Process ID: ", p3.pid, "\nProcess Name: ", nullTerminated($$p3.name), "\nProcess bits: ", p3.bits, "\nProcess Start Time: ", p3.starttime, "\nProcess Path: ", nullTerminated($$p3.path)

## Isprocessalive tests (should return 1)
echo Isprocessalive(p3.addr)
assert Isprocessalive(p3.addr) == 1

## Getprocessbits tests (should return 64(for me, at least))
echo Getsystembits()
assert Getsystembits() == 64

## Getthread tests
var t: threadt
var status4: boolt = Getthread(t.addr)
echo status4
echo "Thread ID: ", t.tid, "\nThread Owner Process ID: ", t.ownerpid

## Getthreadex tests
var t2: threadt
var status5: boolt = Getthreadex(p2.addr, t2.addr)
echo status5
echo "Thread ID: ", t2.tid, "\nThread Owner Process ID: ", t2.ownerpid

## Getthreadprocess tests
var pt: processt
var status6: boolt = Getthreadprocess(t2.addr, pt.addr)
echo status6
echo "Process ID: ", pt.pid, "\nProcess Name: ", nullTerminated($$pt.name), "\nProcess bits: ", pt.bits, "\nProcess Start Time: ", pt.starttime, "\nProcess Path: ", nullTerminated($$pt.path)

## Enumprocesses tests
var
  processList: seq[processt]
  pprocess: processt

proc enumProcessCallback(pproc: ptr processt, arg: pointer): boolt {.cdecl.} =
  processList.add(pproc[])
  result = 1

var status7: boolt = Enumprocesses(enumProcessCallback, nil)
echo status7
echo processList.len
for p in processList:
  echo "Process ID: ", p.pid, "\nProcess Name: ", nullTerminated($$p.name), "\nProcess bits: ", p.bits, "\nProcess Start Time: ", p.starttime, "\nProcess Path: ", nullTerminated($$p.path)


## Enumthreads tests
var
  threadList: seq[threadt]
  pthread: threadt

proc enumThreadCallback(pthread: ptr threadt, arg: pointer): boolt {.cdecl.} =
  threadList.add(pthread[])
  result = 1

var status8: boolt = Enumthreads(enumThreadCallback, nil)
echo status8
echo threadList.len
for t in threadList:
  echo "Thread ID: ", t.tid, "\nThread Owner Process ID: ", t.ownerpid

## Enumthreadsex tests
var
  threadList2: seq[threadt]
  pthread2: threadt

proc enumThreadCallback2(pthread2: ptr threadt, arg: pointer): boolt {.cdecl.} =
  threadList2.add(pthread2[])
  result = 1

var status9: boolt = Enumthreadsex(pprocess.addr, enumThreadCallback2, nil)
echo status9
echo threadList2.len


## Findmodule tests currently not working for me
var
  moduleList: seq[modulet]
  pmodule: modulet

proc enumModuleCallback(pmodule: ptr modulet, arg: pointer): boolt {.cdecl.} =
  moduleList.add(pmodule[])
  result = 1

var status10: boolt = Enummodules(enumModuleCallback, nil)
echo status10
echo moduleList.len
for m in moduleList:
  echo "Module Name: ", nullTerminated($$m.name), "\nModule Path: ", nullTerminated($$m.path)

const test_module = "ntdll.dll"
var m: modulet
var status11: boolt = Findmodule(test_module, m.addr)
echo status11
echo "Module Name: ", nullTerminated($$m.name), "\nModule Path: ", nullTerminated($$m.path), "\nModule Base: ", m.base, "\nModule Size: ", m.size

var m2: modulet
var status12: boolt = Findmoduleex(p2.addr, test_module, m2.addr)
echo status12
echo "Module Name: ", nullTerminated($$m2.name), "\nModule Path: ", nullTerminated($$m2.path), "\nModule Base: ", m2.base, "\nModule Size: ", m2.size


## Loading in the local process seems to work, but unloading does not
## The Ex versions of the functions cant even get imported
const loadtests = r"C:\Windows\System32\FXSEVENT.dll"
const unloadtest = r"C:\Windows\System32\oleaccrc.dll"
var mt: modulet
var status13: boolt = Loadmodule(loadtests, mt.addr)
echo status13
echo Findmodule("FXSEVENT.dll", mt.addr)
echo mt.base
status13 = Unloadmodule(mt.addr)
echo status13