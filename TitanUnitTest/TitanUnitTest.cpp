#include "stdafx.h"
#include "..\SDK\CPP\TitanEngine.h"
#include "TitanScript.h"
#include <iostream>

void log_callback( const char* str, eLogType log_type );

int main(int argc, char* argv[])
{
    if(argc < 3)
    {
        log_callback("Usage: titan_unittest.exe script.osc target.exe", TS_LOG_ERROR);
        return -1;
    }

    if ( !ExtensionManagerIsPluginLoaded( "TitanScript" ) || !ExtensionManagerIsPluginEnabled( "TitanScript" ) )
    {
        throw std::runtime_error( "TitanScript failed to load!" );
    }

    tScripterLoadFileA load_file = GetTSFunctionPointer( LoadFileA );
    tScripterExecuteWithTitanMistA exec = GetTSFunctionPointer( ExecuteWithTitanMistA );
    tScripterSetLogCallback set_log_callback = GetTSFunctionPointer( SetLogCallback );

    set_log_callback(&log_callback );

    if(!load_file(argv[1]))
    {
        log_callback("Error loading script", TS_LOG_ERROR);
        return -1;
    }

    exec(argv[2], "dump.exe" );

    return 0;
}


void log_callback( const char* str, eLogType log_type )
{
    std::cout << str << "\n" << std::flush;
}

