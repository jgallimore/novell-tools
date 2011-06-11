/* General header file for NLMs compiled under Linux
   This must be included before any other header!!! */
/*
   Copyright (C) 1999 by Gabor Keresztfalvi <keresztg@mail.com>
	
   You can use this file for any of your program without restriction.
	
   THIS PROGRAM IS PROVIDED 'AS IS' WITHOUT WARRANTY OF ANY KIND. IN NO EVENT
   I AM LIABLE TO YOU FOR DAMAGES, INCLUDING GENERAL, NOT SO GENERAL, SERVER
   BURNING DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE THIS PROGRAM.
   ALWAYS USE TEST SERVERS FOR DEVELOPMENT SEPARATED FROM PRODUCTION SERVERS!
   AND DON'T FORGET: THE NETWARE SERVER OPERATING SYSTEM ENVIRONMENT DOESN'T
   TOLERATE PROGRAMMING FAULTS AND IS NOT FOR BEGINNERS IN C!
*/


#ifndef __GENLM_H__
#define __GENLM_H__

#define _FIND_OLD_HEADERS_

#define N_PLAT_NLM

#ifdef __GNUC__
#include <ntypes.h>
  #ifdef N_FAR
   #undef N_FAR
  #endif /* N_FAR */
  #ifdef N_CDECL
   #undef N_CDECL
  #endif /* N_CDECL */
 #define N_FAR
 #define N_CDECL
#endif /* __GNUC__ */

#endif /* __GENLM_H__ */

