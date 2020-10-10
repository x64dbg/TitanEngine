/*
 * aPLib compression library  -  the smaller the better :)
 *
 * COFF format header file
 *
 * Copyright (c) 1998-2014 Joergen Ibsen
 * All Rights Reserved
 *
 * http://www.ibsensoftware.com/
 */

#ifndef APLIB_H_INCLUDED
#define APLIB_H_INCLUDED

#define APLIB_CONVENTION

#ifdef __cplusplus
extern "C" {
#endif

#ifndef APLIB_ERROR
# define APLIB_ERROR ((unsigned int) (-1))
#endif

unsigned int APLIB_CONVENTION aP_pack(const void* source,
                                      void* destination,
                                      unsigned int length,
                                      void* workmem,
                                      int (__cdecl* callback)(unsigned int, unsigned int, unsigned int, void*),
                                      void* cbparam);

unsigned int APLIB_CONVENTION aP_workmem_size(unsigned int inputsize);

unsigned int APLIB_CONVENTION aP_max_packed_size(unsigned int inputsize);

unsigned int APLIB_CONVENTION aP_depack_asm(const void* source, void* destination);

unsigned int APLIB_CONVENTION aP_depack_asm_fast(const void* source, void* destination);

inline unsigned int APLIB_CONVENTION aP_depack_asm_safe(const void* source,
        unsigned int srclen,
        void* destination,
    unsigned int dstlen)
{
    return 0;
}

unsigned int APLIB_CONVENTION aP_crc32(const void* source, unsigned int length);

unsigned int APLIB_CONVENTION aPsafe_pack(const void* source,
        void* destination,
        unsigned int length,
        void* workmem,
        int (__cdecl* callback)(unsigned int, unsigned int, unsigned int, void*),
        void* cbparam);

unsigned int APLIB_CONVENTION aPsafe_check(const void* source);

unsigned int APLIB_CONVENTION aPsafe_get_orig_size(const void* source);

inline unsigned int APLIB_CONVENTION aPsafe_depack(const void* source,
    unsigned int srclen,
    void* destination,
    unsigned int dstlen)
{
    return 0;
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* APLIB_H_INCLUDED */
