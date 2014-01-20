This is a bugfixed & enhanced version of TitanEngine v2.0.3

The following things have been fixed/added (list might be incomplete):
- fixed memory breakpoints in general
- fixed harware breakpoints in general
- only report exceptions that are unhandled by the debugger
- working on x64 (previously there was a structure alignment problem)
- some code commenting
- fixed DumpProcessExW (found/fix provided by Aguila)
- added a callback on the system breakpoint
- added memory breakpoints on execute
- added QWORD hardware breakpoints
- smaller and faster DLL loaders
- supports multiple calling conventions (including the callbacks)
- MinGW import libraries
- fixed exception handling
- Importer functions use Scyllas business logic now, much more accurate
- updated distorm lib to v3, was v1
- countless code improvements

NOTE: LUA, Python, MASM and Delphi might not work correctly
      Mainly because their headers havent been adjusted 
      to these changes. However this is easy. Compare with 
      C/C++ headers, fix it up and send us.
      
      
If you are good with these kinda codes, please help review, do pull-requests, 
and criticize what you think can be be improved !

You can discuss with us here 
http://forum.tuts4you.com/forum/138-titanengine-community-edition/