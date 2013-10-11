This is a fixed version of TitanEngine v2.0.3

The following things have been fixed/added (list might be incomplete):
- fixed memory breakpoints in general
- fixed harware breakpoints in general
- only report exceptions that are unhandled by the debugger
- working on x64 (previously there was a structure alignment problem)
- exported everything as extern "C" (for compatibility with MingW compiler on x64)
- some code commenting
- fixed DumpProcessExW (found/fix provided by Aguila)
- added a callback on the system breakpoint
- added memory breakpoints on execute
- added QWORD hardware breakpoints
- general code fixes
- smaller and better DLL loaders

