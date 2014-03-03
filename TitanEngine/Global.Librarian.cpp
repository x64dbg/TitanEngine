#include "stdafx.h"
#include "definitions.h"
#include "Global.Librarian.h"

// Global.Engine.Librarian:
LIBRARY_ITEM_DATA LibraryInfoData = {};
LPVOID LibrarianData = VirtualAlloc(NULL, MAX_LIBRARY_BPX * sizeof LIBRARY_BREAK_DATA, MEM_COMMIT, PAGE_READWRITE);
LPVOID hListLibrary = 0;