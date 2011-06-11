#
#  A sample Makefile for the NetWare loadable modules making
#  on Linux and Win32 (Cygwin) platforms with the GNU utilities
#
#  Written by Pavel Novy <novy@feld.cvut.cz>
#  Version 1.0.22 (2002-02-20)
#

NLMSTUFF      := $(NLMSTUFF)
NDKLIB         = #$(LIBC)

TARGET         = nwrights
BUILD          =
MAKEFILE       = Makefile# $(TARGET).Makefile
CFLAGS         = #-save-temps #-v
DEFINES        = -DN_PLAT_NLM
INCLUDES       =
LIBRARIES      =
SOURCE_DEP     =
TARGET_DEP     =
OPTLEVEL       =
SOURCES        = $(TARGET).c

DESCRIPTION    = NetWare Rights Utility
VERSION        = 1,0,0
DATE           =
COPYRIGHT      = Copyright 2003 J. Gallimore
THREADNAME     = $(TARGET)_p
SCREENNAME     = $(DESCRIPTION)#NONE

TYPE           = nlm# | o | nlm | lan | dsk | nam | a
OPTIONS        = #debug multiple os_domain pseudopreemption reentrant synchronize
FLAG_ON        = #64 for autounload
XDCDATA        =
START          =
EXIT           =
CHECK          =
STACK          = 8192
PRELUDE        = $(NLMSTUFF)/imports/nwpre.o# $(NDKLIB)/imports/libcpre.gcc.o
EXPORTS        =
IMPORTS        = NWDSFreeContext, NWDSLogout, NWAddTrustee, NWDSAuthenticateConn, NWIntScanForTrustees, NWScanNSEntryInfo2, NWDeleteTrustee, NWDeallocateDirectoryHandle, NWGetLongName, NWGetNSPath, NWCCCloseConn, NWIsDSAuthenticated, NWDSCreateContextHandle, NWDSMapNameToID, NWDSMapIDToName, NWAllocTempNSDirHandle2, NWDSSetContext, NWSetNSEntryDOSInfo, NWDSLogin, NWGetNSEntryInfo, NWCCOpenConnByName
EXPORTFILES    =
IMPORTFILES    = clib# libc
MODULES        = clib# libc

include $(NLMSTUFF)/Makefile.GNU
