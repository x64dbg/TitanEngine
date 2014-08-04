#ifndef _GLOBAL_ENGINE_HASH_H
#define _GLOBAL_ENGINE_HASH_H

void HashInit();
unsigned long EngineCrc32Reflect(unsigned long ulReflect, const char cChar);
void EngineCrc32PartialCRC(unsigned long* ulCRC, const unsigned char* sData, unsigned long ulDataLength);

#endif //_GLOBAL_ENGINE_HASH_H