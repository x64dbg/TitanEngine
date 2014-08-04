#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.Hash.h"

static unsigned long Crc32Table[256];

// Global.Engine.Hash.functions:
void HashInit()
{
    unsigned long ulPolynomial = 0x04C11DB7; //0x04C11DB7 is the official polynomial used by PKZip, WinZip and Ethernet.
    // CRC32 table initialization
    for(int iCodes = 0; iCodes <= 0xFF; iCodes++)
    {
        Crc32Table[iCodes] = EngineCrc32Reflect(iCodes, 8) << 24;
        for(int iPos = 0; iPos < 8; iPos++)
        {
            Crc32Table[iCodes] = (Crc32Table[iCodes] << 1) ^ ((Crc32Table[iCodes] & (1 << 31)) ? ulPolynomial : 0);
        }
        Crc32Table[iCodes] = EngineCrc32Reflect(Crc32Table[iCodes], 32);
    }
}

unsigned long EngineCrc32Reflect(unsigned long ulReflect, const char cChar)
{

    unsigned long ulValue = 0;

    // Swap bit 0 for bit 7, bit 1 For bit 6, etc....
    for(int iPos = 1; iPos < (cChar + 1); iPos++)
    {
        if(ulReflect & 1)
        {
            ulValue |= (1 << (cChar - iPos));
        }
        ulReflect >>= 1;
    }
    return ulValue;
}

void EngineCrc32PartialCRC(unsigned long* ulCRC, const unsigned char* sData, unsigned long ulDataLength)
{

    while(ulDataLength--)
    {
        //If your compiler complains about the following line, try changing each
        //  occurrence of *ulCRC with "((unsigned long)*ulCRC)" or "*(unsigned long *)ulCRC".
        *(unsigned long*)ulCRC = ((*(unsigned long*)ulCRC) >> 8) ^ Crc32Table[((*(unsigned long*)ulCRC) & 0xFF) ^ *sData++];
    }
}