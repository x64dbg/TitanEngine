#include "stdafx.h"
#include "definitions.h"
#include "Global.Librarian.h"

// Global.Engine.Librarian:
std::vector<LIBRARY_ITEM_DATAW> hListLibrary;
std::vector<LIBRARY_BREAK_DATA> LibrarianData;

void ClearLibraryList()
{
    std::vector<LIBRARY_ITEM_DATAW>().swap(hListLibrary);
}
