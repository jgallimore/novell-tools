/*  
 *  Copyright 2003 Jonathan Gallimore
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *
 *  12/11/2003: Initial Release
 *  17/11/2003: Added support for adding and removing trustee rights
 *  21/11/2003: Added support for inherited rights filters and +/- syntax
 *  28/11/2003: Added command line support to display trustee rights for a given path
 *  30/11/2003: Added command line support to assign trustee rights and IRFs
 *  07/11/2003: Implemented Sig Handler and used ungetch to allow safe unloading
 *  17/11/2003: Added copyright notice, cleaned up Usage(), added code to override login for no parameters
 *              and added code to interpret cx in Restore()
 *  07/05/2004: Added a pause to the output, and a log option for restoring rights
 *
 */ 

/*
 *  To-do:
 *  
 *  1. Cross platform compile
 *  2. Namespace switch
 *
 */
 
/* v1.1 to-do list
 *
 * 1. Clean up and standardise output
 * 2. Find out if there are any redirections for stdout and stderr on Netware - usually > and >>
 * 3. Scrolling
 *
 */

#include "gennlm.h"
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <nwconio.h>
#include <signal.h>
#include <nwnet.h>
#include <nwcalls.h>
#include <nwclxcon.h>
#include <nlm\nit\nwenvrn.h>
#include <nwthread.h>

#define KEY_ENTER 343

/*
 * Define error codes for functions
 */
 
#define SUCCESS 		 0
#define ERR_FILE_INFO 		-1
#define ERR_TRUSTEE_TO_NDS_OBJ 	-2
#define ERR_NDS_OBJ_TO_TRUSTEE 	-3
#define ERR_CANT_ASSIGN_RIGHTS 	-4
#define ERR_CANT_SET_FILTER	-5

/*
 *  Function prototypes
 *
 */

void 	Cleanup 	(void);
void 	SigHandler 	(int sig);
void 	Usage 		(void);
void 	Restore 	(NWCONN_HANDLE ConnHandle, char* FileName, char* Logfile);
char* 	GetParam 	(char* ParamStr, char* Buffer, int BufferSize);
int 	GetOptArgs 	(int argc, char* argv[], char* Username, char* Password, char* Logfile);
int 	TrimQuotes 	(char* Dest, char* Src, int DestSize);
void 	GetPass 	(char *Pass, int Len);
int 	InheritedRights (NWCONN_HANDLE ConnHandle, NWDIR_HANDLE DirHandle, pnstr8 Path, nuint16 NameSpace, pnstr8 Rights);
int 	TrusteeRights 	(NWCONN_HANDLE ConnHandle, NWDIR_HANDLE DirHandle, pnstr8 Path, nuint16 NameSpace, pnstr8 TrusteeName, pnstr8 Rights);
int 	GetTrustees 	(NWCONN_HANDLE ConnHandle, NWDIR_HANDLE DirHandle, pnstr8 Path, nuint16 NameSpace, nuint16 SubDir, FILE* fh);
int 	GetShortPath 	(NWCONN_HANDLE ConnHandle, NWDIR_HANDLE DirHandle, pnstr8 Path, nuint8 NameSpace, pnstr8 Buffer, nuint32 BufferSize, pnuint16 Flag);
void 	DisplayOutput (char* File, char* Rights, char* Trustee, int Errcode, FILE* Logfile);

/*
 *  Custom type for changing trustee rights
 *
 */

typedef enum 
{
        Add,
        Revoke,
        Set,
        Delete
} 
TrusteeRightsOp;

/*
 *  Global variables
 *
 */

int                     DoLogin;		// if we do a login, also logout
NWDSContextHandle       NDSContext;		// global variable to hold context
BYTE                    AutoDestroyScreen;	// work out if we want to automatically destroy the screen
int			MainThreadGroupId;	// id for main thread group
int			ThreadCount = 0;	// counter for number of threads to ensure we've cleaned up ok
int			NlmExiting = FALSE;	// set from the sig handler when unload is called
int			AwaitingInput = FALSE;	// set when the NLM is waiting input so sigterm can unblock if needed
int			Pause;

/*
 *  GetShortPath function 
 *
 *  Converts a filename in the given namespace to the short Netware
 *  version, and copies it to the given buffer, after checking for length
 *
 */

int GetShortPath (NWCONN_HANDLE ConnHandle, NWDIR_HANDLE DirHandle, pnstr8 Path, nuint8 NameSpace, pnstr8 Buffer, nuint32 BufferSize, pnuint16 Flag)
{
        NWDSCCODE       res;                    // Variable to store the return code
        NW_NS_PATH      NSPath;                 // NSPath structure for converting filenames with NWGetNSPath
        NW_ENTRY_INFO   EntryInfo;              // Stores information about the file or folder
        nstr8           DosPath [256];          // DOS Path name
        nstr8           DosName [256];          // DOS filename
        nuint16         FileFlag;               // File flag - 1 for file, 0 for folder

        // Get the Namespace info to find out if its a file or a folder

        if ((res = NWGetNSEntryInfo (ConnHandle, DirHandle, Path, NameSpace, NameSpace, SA_ALL, IM_ATTRIBUTES | IM_RIGHTS | IM_NAME, &EntryInfo)) != 0)
                printf ("NWGetNSEntryInfo returned: %d\n", res);

        // Populate the NSPath structure

        NSPath.srcPath = Path;
        NSPath.dstPath = DosPath;
        NSPath.dstPathSize = 256;

        // Call the NWGetNSPath Api function with the appropriate file flag to get the full DOS path

        if ((EntryInfo.attributes & A_DIRECTORY) == A_DIRECTORY)
        {
                FileFlag = 0;
                if ((res = NWGetNSPath (ConnHandle, DirHandle, FileFlag, NameSpace, NW_NS_DOS, &NSPath)) != 0)
                        printf ("NWGetNSPath returned: %d\n", res);
        }
        else
        {
                FileFlag = 1;
                if ((res = NWGetNSPath (ConnHandle, DirHandle, FileFlag, NameSpace, NW_NS_DOS, &NSPath)) != 0)
                        printf ("NWGetNSPath returned: %d\n", res);

                if ((res = NWGetLongName (ConnHandle, DirHandle, Path, NameSpace, NW_NS_DOS, DosName)) != 0)
                        printf ("NWGetLongName returned: %d\n", res);

                if ((strlen (DosPath) + strlen (DosName)) < 255)
                {
                        strcat (DosPath, "\\");
                        strcat (DosPath, DosName);
                }
        }

        // Check the buffer is big enough, and copy the string

        if (strlen (DosName) < BufferSize)
        {
                strcpy (Buffer, DosPath);
                *Flag = FileFlag;
                return 0;
        }
        else
                return (strlen (DosName)); // otherwise return the size needed
}

/*
 *  Get Trustees function
 *
 *  Given a directory handle (can be 0) and a path relative to the directory handle
 *  this function will print all the trustee rights and inherited rights filters
 *  for the given path, and any subfolders
 *
 *  if a file pointer is passed, the function will also write commands to a file
 *  much like Tbackup.
 *
 */

int GetTrustees (NWCONN_HANDLE ConnHandle, NWDIR_HANDLE DirHandle, pnstr8 Path, nuint16 NameSpace, nuint16 SubDir, FILE* fh)
{
        int              i;                             // Used for iterating through trustee lists
        NW_ENTRY_INFO*   EntryInfo;                     // Netware structure for file / folder info
        NW_ENTRY_INFO2*  Children;                      // List of child files and folders
        NWET_INFO*       TrusteeInfo;                   // Netware structure for holding a list of trustees
        nuint16          NumEntries;                    // Pointer to the number of entries returned by NDS Api functions
        SEARCH_SEQUENCE* Seq;                           // Sequence number used by NDS Api
        NWDSCCODE        res;                           // Variable to store the result of functions - 0=Success
        nuint16          FileFlag;                      // Specifies a file or folder
        nuint32          IterHandle;                    // Iteration handle for NDS functions
        pnstr8           Trustee;                       // String to hold trustee name after its been converted from ObjectID
        pnstr8           IRights;                       // String represent the inherited rights filter
        pnstr8           Rights;                        // String to represent rights
        pnstr8           DosPath;                       // String to hold Path converted to Netware (DOS) notation
        NWDIR_HANDLE*    TempDirHandle;                 // Temporary directory handle to use for getting subfolders
        pnstr8           NextPath;                      // String to hold the name of the subfolder

        EntryInfo       = (NW_ENTRY_INFO*)      malloc (sizeof (NW_ENTRY_INFO));
        TrusteeInfo     = (NWET_INFO*)          malloc (sizeof (NWET_INFO));
        Trustee         = (pnstr8)              malloc (sizeof (nstr8) * MAX_DN_CHARS+1);
        IRights         = (pnstr8)              malloc (sizeof (nstr8) * 10);
        Rights          = (pnstr8)              malloc (sizeof (nstr8) * 10);
        DosPath         = (pnstr8)              malloc (sizeof (nstr8) * 256);
        
        if (EntryInfo && TrusteeInfo && Trustee && IRights && Rights && DosPath)
        {
        
                // Find out whether Path is a file or folder, and get the inherited rights filter

                if ((res = NWGetNSEntryInfo (ConnHandle, DirHandle, Path, NW_NS_LONG, NW_NS_LONG, SA_ALL, IM_ATTRIBUTES | IM_RIGHTS | IM_NAME, EntryInfo)) != 0)
                        printf ("NWGetNSEntryInfo returned: %d\n", res);

                // Print the inherited rights as a string - all the rights are ORed together to make an nuint16.
        
                if ((EntryInfo->inheritedRightsMask & TA_ALL) != TA_ALL)
                {
                        strcpy (IRights, "");
                        if ((EntryInfo->inheritedRightsMask & TA_NONE)          == TA_NONE)     strcat (IRights, "S");
                        if ((EntryInfo->inheritedRightsMask & TA_READ)          == TA_READ)     strcat (IRights, "R");
                        if ((EntryInfo->inheritedRightsMask & TA_WRITE)         == TA_WRITE)    strcat (IRights, "W");
                        if ((EntryInfo->inheritedRightsMask & TA_CREATE)        == TA_CREATE)   strcat (IRights, "C");
                        if ((EntryInfo->inheritedRightsMask & TA_DELETE)        == TA_DELETE)   strcat (IRights, "E");
                        if ((EntryInfo->inheritedRightsMask & TA_MODIFY)        == TA_MODIFY)   strcat (IRights, "M");
                        if ((EntryInfo->inheritedRightsMask & TA_SEARCH)        == TA_SEARCH)   strcat (IRights, "F");
                        if ((EntryInfo->inheritedRightsMask & TA_OWNERSHIP)     == TA_OWNERSHIP)strcat (IRights, "A");

                        // printf ("%s\t%s\t/F\n", Path, IRights);
			DisplayOutput (Path, IRights, "/F", SUCCESS, NULL);
			if (fh)
				fprintf (fh,"RIGHTS \"%s\" %s /F\n", Path, IRights); 

                }

                // Get the short path name, as NWIntScanForTrustees will only work with the default name space

                if ((res = GetShortPath (ConnHandle, DirHandle, Path, NameSpace, DosPath, 256, &FileFlag)) != 0)
                {
                        printf ("GetShortPath returned: %d\n", res);
                        return 1;
                }

                IterHandle = 0;
                
                // Iteratively scan for trustees until there are no more

                while (NWIntScanForTrustees (ConnHandle, 0, DosPath, &IterHandle, &NumEntries, TrusteeInfo, 0) == 0)
                {

                        // arrays of 20 trustees are returned

                        for (i=0;i<20;i++)
                        {
                                // if an entry hasn't been populated, it is set to 0L

                                if (TrusteeInfo->trusteeList[i].objectID != 0L)
                                {
                                        // An object id is returned representing a trustee, so convert to a string

                                        if ((res = NWDSMapIDToName (NDSContext, ConnHandle, TrusteeInfo->trusteeList[i].objectID, Trustee)) != 0)
                                                printf ("NWDSMapIDToName returned: %d\n", res);
                                        else
                                        {
                                                // Convert the rights to a string, again rights are ORed together

                                                strcpy (Rights, "");
                                                if ((TrusteeInfo->trusteeList[i].objectRights & TR_SUPERVISOR)  == TR_SUPERVISOR)       strcat (Rights, "S");
                                                if ((TrusteeInfo->trusteeList[i].objectRights & TR_READ)        == TR_READ)             strcat (Rights, "R");
                                                if ((TrusteeInfo->trusteeList[i].objectRights & TR_WRITE)       == TR_WRITE)            strcat (Rights, "W");
                                                if ((TrusteeInfo->trusteeList[i].objectRights & TR_CREATE)      == TR_CREATE)           strcat (Rights, "C");
                                                if ((TrusteeInfo->trusteeList[i].objectRights & TR_DELETE)      == TR_DELETE)           strcat (Rights, "E");
                                                if ((TrusteeInfo->trusteeList[i].objectRights & TR_MODIFY)      == TR_MODIFY)           strcat (Rights, "M");
                                                if ((TrusteeInfo->trusteeList[i].objectRights & TR_FILE_SCAN)   == TR_FILE_SCAN)        strcat (Rights, "F");
                                                if ((TrusteeInfo->trusteeList[i].objectRights & TR_ACCESS_CTRL) == TR_ACCESS_CTRL)      strcat (Rights, "A");
                                                //printf ("%s\t%s\t/NAME=%s\n", Path, Rights, Trustee);
						DisplayOutput (Path, Rights, Trustee, SUCCESS, NULL);

                                                if (fh)
                                                        fprintf (fh,"RIGHTS \"%s\" %s /NAME=\"%s\"\n", Path, Rights, Trustee); 
                                        }
                                }
                        }
                }

                // If we're examining a directory, then scan files and folder within the directory
		
		// NOTE: all the variable assigned here are malloc'ed so that only the pointers go on the stack
		//       in recursive calls. I changed this because I was getting some stack overflow problems
		//       on large directory structure on NW5.1

                // added a check to see if the NLM was exiting via the sig handler - if it is, stop processing and clean up
		
		if (((EntryInfo->attributes & A_DIRECTORY) == A_DIRECTORY) && (SubDir != 0) && (NlmExiting == FALSE))
                {
                        Children        = (NW_ENTRY_INFO2*)     malloc (sizeof (NW_ENTRY_INFO2));
                        Seq             = (SEARCH_SEQUENCE*)    malloc (sizeof (SEARCH_SEQUENCE));
                        TempDirHandle   = (NWDIR_HANDLE*)       malloc (sizeof (NWDIR_HANDLE));
                        
                        if (Children && Seq && TempDirHandle)
                        {

                                if ((res = NWAllocTempNSDirHandle2 (ConnHandle, DirHandle, Path, NW_NS_LONG, TempDirHandle, NW_NS_LONG)) != 0)
                                        printf ("NWAllocTempNSDirHandle2 returned: %d\n", res);

                                Seq->searchDirNumber = -1;
                                while (NWScanNSEntryInfo2 (ConnHandle, *TempDirHandle, NW_NS_LONG, SA_ALL, Seq, "*" ,IM_NAME, Children) == 0)
                                {
                                        if ((NextPath = (char*) malloc (sizeof (char) * (strlen (Children->entryName) + strlen (Path) + 2))) == NULL)
                                                printf ("Couldn't allocate memory\n");
                                        else
                                        {
                                                strcpy (NextPath, Path);
                                                strcat (NextPath, "\\");
                                                strcat (NextPath, Children->entryName);

                                                // Iterativly call GetTrustees on subfolders

                                                GetTrustees (ConnHandle, 0, NextPath, NameSpace, SubDir, fh);
                                                free (NextPath);
                                        }
                                }

                                NWDeallocateDirectoryHandle (ConnHandle, *TempDirHandle);
                        }
                        
                        if (Children) free (Children);
                        if (Seq) free (Seq);
                        if (TempDirHandle) free (TempDirHandle);
                                                
                }
        }
        
	// cleanup
	
        if (EntryInfo)          free (EntryInfo);
        if (TrusteeInfo)        free (TrusteeInfo);
        if (Trustee)            free (Trustee);
        if (IRights)            free (IRights);
        if (Rights)             free (Rights);
        if (DosPath)            free (DosPath);

        return 0;
}

/*
 *  TrusteeRights function
 *
 *  Assigns trustee rights based on string passed in representing the rights, and another representing the trustee
 *  Works with the RWCEMFSA and the +/- syntax
 *
 */

int TrusteeRights (NWCONN_HANDLE ConnHandle, NWDIR_HANDLE DirHandle, pnstr8 Path, nuint16 NameSpace, pnstr8 TrusteeName, pnstr8 Rights)
{
        nuint32         ObjectID;                       // Variable to hold the Object ID (converted from TrusteeName)
        nuint16         ObjectRights;                   // Holds the binary representation of the rights
        nuint16         FileFlag;                       // Specifies a file or folder
        NWDSCCODE       res;                            // Holds NDS Api return codes
        nuint32         IterHandle;                     // Iterator handle for internal use by NDS Api
        nuint16         NumEntries;                     // Number of entries returned by NWIntScanForTrustees
        NWET_INFO       TrusteeInfo;                    // Array of trustees and rights
        nstr8           DosPath [256];                  // String to represent DOS path
        nstr8           Trustee [MAX_DN_CHARS + 1];     // String to hold trustee
        TrusteeRightsOp RightsOp;                       // Stores which operation were carrying out for if statements
        int             i;                              // Used for iterating through trustee array

        // Get the short path name

        if ((res = GetShortPath (ConnHandle, DirHandle, Path, NameSpace, DosPath, 256, &FileFlag)) != 0)
		return ERR_FILE_INFO;

        ObjectRights = TR_NONE;

        // Work out which operation were doing - + indicate adding, - is revoking, REM is deleting, anything else is assign

        if (Rights [0] == '+')
                RightsOp = Add;
        else if (Rights [0] == '-')
                RightsOp = Revoke;
        else if (stricmp (Rights, "REM") == 0)
                RightsOp = Delete;
        else
                RightsOp = Set;

        // COnvert Trustee to an ObjectID

        if ((res = NWDSMapNameToID (NDSContext, ConnHandle, TrusteeName, &ObjectID)) != 0)
                return ERR_TRUSTEE_TO_NDS_OBJ;

        // If we're adding or revoking, we need to know the objects original rights

        if (RightsOp == Add || RightsOp == Revoke)
        {
                TrusteeInfo.sequenceNumber = 0L;
                IterHandle = 0;

                // Get rights for the path

                while (NWIntScanForTrustees (ConnHandle, 0, DosPath, &IterHandle, &NumEntries, &TrusteeInfo, 0) == 0)
                {
                        for (i=0;i<20;i++)
                        {
                                // Scan for given trustee and obtain rights

                                if (TrusteeInfo.trusteeList[i].objectID != 0L)
                                {
                                        if ((res = NWDSMapIDToName (NDSContext, ConnHandle, TrusteeInfo.trusteeList[i].objectID, Trustee)) == 0)
                                                if (ObjectID == TrusteeInfo.trusteeList[i].objectID) ObjectRights = TrusteeInfo.trusteeList[i].objectRights;
                                }
                        }               
                }
        }

        // If we are adding rights, we can simply OR the new rights with the old
        // which will be TR_NONE in the case of Set

        if (RightsOp == Add || RightsOp == Set)
        {
                for (i=0;i<strlen (Rights);i++)
                {
                        if (Rights [i] == 'S' || Rights [i] == 's') ObjectRights = ObjectRights | TR_SUPERVISOR;
                        if (Rights [i] == 'R' || Rights [i] == 'r') ObjectRights = ObjectRights | TR_READ;
                        if (Rights [i] == 'W' || Rights [i] == 'w') ObjectRights = ObjectRights | TR_WRITE;
                        if (Rights [i] == 'C' || Rights [i] == 'c') ObjectRights = ObjectRights | TR_CREATE;
                        if (Rights [i] == 'E' || Rights [i] == 'e') ObjectRights = ObjectRights | TR_DELETE;
                        if (Rights [i] == 'M' || Rights [i] == 'm') ObjectRights = ObjectRights | TR_MODIFY;
                        if (Rights [i] == 'F' || Rights [i] == 'f') ObjectRights = ObjectRights | TR_FILE_SCAN;
                        if (Rights [i] == 'A' || Rights [i] == 'a') ObjectRights = ObjectRights | TR_ACCESS_CTRL;
                }
        }
        
        // If we are revoking rights, we need to XOR the appropriate right with TR_ALL, and then AND it with the old rights

        if (RightsOp == Revoke)
        {
                for (i=0;i<strlen (Rights);i++)
                {
                        if (Rights [i] == 'S' || Rights [i] == 's') ObjectRights = (TR_SUPERVISOR       ^ TR_ALL) & ObjectRights;
                        if (Rights [i] == 'R' || Rights [i] == 'r') ObjectRights = (TR_READ             ^ TR_ALL) & ObjectRights;
                        if (Rights [i] == 'W' || Rights [i] == 'w') ObjectRights = (TR_WRITE            ^ TR_ALL) & ObjectRights;
                        if (Rights [i] == 'C' || Rights [i] == 'c') ObjectRights = (TR_CREATE           ^ TR_ALL) & ObjectRights;
                        if (Rights [i] == 'E' || Rights [i] == 'e') ObjectRights = (TR_DELETE           ^ TR_ALL) & ObjectRights;
                        if (Rights [i] == 'M' || Rights [i] == 'm') ObjectRights = (TR_MODIFY           ^ TR_ALL) & ObjectRights;
                        if (Rights [i] == 'F' || Rights [i] == 'f') ObjectRights = (TR_FILE_SCAN        ^ TR_ALL) & ObjectRights;
                        if (Rights [i] == 'A' || Rights [i] == 'a') ObjectRights = (TR_ACCESS_CTRL      ^ TR_ALL) & ObjectRights;
                }
        }

        // Call NWAddTrustee, unless we're deleting a trustee

        if (RightsOp != Delete)
        {
                if ((res = NWAddTrustee (ConnHandle, DirHandle, DosPath, ObjectID, ObjectRights)) != 0)
			return ERR_CANT_ASSIGN_RIGHTS;
                else
                        return SUCCESS;
        }

        // Otherwise call NWDeleteTrustee

        else
        {
                if ((res = NWDeleteTrustee (ConnHandle, DirHandle, DosPath, ObjectID)) != 0)
                        return ERR_CANT_ASSIGN_RIGHTS;
                else
                        return SUCCESS;
        }
}

/*
 *  Inherited Rights function
 *
 *  sets the inherited rights filter for an directory
 *  supports the +/- syntax
 *
 */

int InheritedRights (NWCONN_HANDLE ConnHandle, NWDIR_HANDLE DirHandle, pnstr8 Path, nuint16 NameSpace, pnstr8 Rights)
{
        MODIFY_DOS_INFO InfoSettings;
        NWDSCCODE       res;
        NW_ENTRY_INFO   EntryInfo;
        TrusteeRightsOp RightsOp;
        nuint16         NewRights;
        int             i;

        // see if a plus or a minus is set - if so we are revoking or adding to the filter, rather than setting it
	
	if (Rights [0] == '+')
                RightsOp = Add;
        else if (Rights [0] == '-')
                RightsOp = Revoke;
        else
                RightsOp = Set;

	// get the directory's current IRF
	
        NWGetNSEntryInfo (ConnHandle, DirHandle, Path, NW_NS_LONG, NW_NS_LONG, SA_ALL, IM_ATTRIBUTES | IM_RIGHTS | IM_NAME, &EntryInfo);

        // start off with no rights to add before processing the rights string
	
	NewRights = TA_NONE;

        // go through the rights string - if the relevant character appears OR the right with NewRights
	
	for (i=0;i<strlen(Rights);i++)
        {
                if (Rights [i] == 'R' || Rights [i] == 'r') NewRights = NewRights | TA_READ;
                if (Rights [i] == 'W' || Rights [i] == 'w') NewRights = NewRights | TA_WRITE;
                if (Rights [i] == 'C' || Rights [i] == 'c') NewRights = NewRights | TA_CREATE;
                if (Rights [i] == 'E' || Rights [i] == 'e') NewRights = NewRights | TA_DELETE;
                if (Rights [i] == 'M' || Rights [i] == 'm') NewRights = NewRights | TA_MODIFY;
                if (Rights [i] == 'F' || Rights [i] == 'f') NewRights = NewRights | TA_SEARCH;
                if (Rights [i] == 'A' || Rights [i] == 'a') NewRights = NewRights | TA_OWNERSHIP;
        }

        // work out the inheritance grant and revoke masks - its best to revoke all and grant only what's necessary
	// in the case of revoking, grant none, and revoke the selected rights
	
	if (RightsOp == Add)
        {
                InfoSettings.inheritanceGrantMask = NewRights | EntryInfo.inheritedRightsMask;
                InfoSettings.inheritanceRevokeMask  = TA_ALL;
        }
        else if (RightsOp == Revoke)
        {
                InfoSettings.inheritanceGrantMask = TA_NONE;
                InfoSettings.inheritanceRevokeMask  = NewRights;
        }
        else if (RightsOp == Set)
        {
                InfoSettings.inheritanceGrantMask = NewRights;
                InfoSettings.inheritanceRevokeMask  = TA_ALL;
        }

        // set the rights
	
	if ((res = NWSetNSEntryDOSInfo (ConnHandle, DirHandle, Path, NameSpace, SA_ALL, DM_INHERITED_RIGHTS_MASK, &InfoSettings)) != 0)
                return ERR_CANT_SET_FILTER;
        else
                return SUCCESS;
}

/*
 *  GetPass function
 *
 *  calls getch and masks the imput with *s to allow a password to be entered securely
 *
 */
 
void GetPass (char *Pass, int Len)
{
        int     index = 0;
        WORD    x,y;

	// Get the y co-ordinate
        y = wherey ();

        do   
        {
                // get the current x co-ordinate
		
		x = wherex ();
                
		// get the next character from the input buffer
		Pass [index] = (char) getch ();
		
		// if its an enter, terminate the string
                if (Pass [index] == 0x0D)
                        Pass [index] = '\0';
		
		// if its a delete move the cursor back, and remove the last character from the string
                else if (Pass [index] == 0x08)
                {
                        if (index-1 >= 0)
                        {
                                index -= 2;
                                
				// blank out the last *
				gotoxy ((WORD) (x-1), y);
                                putch (' ');
                                gotoxy ((WORD) (x-1), y);
                        }
                        else 
                        {
                                index = -1;
                        }
                }
                else
			// display a * for the character
                        putch ('*');
		
		// move to the next character in the array
                index++;
        } while (Pass [index-1] && index < Len);

        
	// apply a newline character if needed
	if (Pass [index-1])
                Pass [index-1] = NULL;
        putch ('\n');
}

/*
 *  TrimQuotes function
 *
 *  removes leading and trailing quotes from a string
 *
 */

int TrimQuotes (char* Dest, char* Src, int DestSize)
{
        char*   p;
        int     l;

        p = Src;
        l = strlen (p);

        // if the string starts with a ", move to the next character, and decrement l by one
	if (*p == '"')
        {
                p++; l--;
                if (l > 0)
                        
			// if last character is a ", decrement l again
			if (p [l-1] == '"') l--;
        }

        // copy l characters starting at p to the destination string
	
	if (DestSize > l)
        {
                strncpy (Dest, p, l);
                Dest [l] = '\0';
                return 0;
        }
        else
                return l;       
}

/*
 *  GetOptArgs function
 *
 *  retrieve optional arguments (username and password) into buffers, and return number of arguments left
 *  NOTE: string lengths have been assumed - some length checking would be good, but given that this function is
 *        only used in this program, it should be ok
 */

int GetOptArgs (int argc, char* argv[], char* Username, char* Password, char* Logfile)
{
        int     args;
        int     i;

        args = argc;

        // Clear username and password

        strcpy (Username, "");
        strcpy (Password, "");
	Pause = 0;

        // Loop through all the arguments

        for (i=1;i<argc;i++)
        {
                // copy pointer to the appropriate string, removing leading and trailing quotes

                if (strncmp (argv[i], "/U=", 3) == 0 || strncmp (argv[i], "/u=", 3) == 0)
                {
                        args--;
                        TrimQuotes (Username, argv[i] + 3, NW_MAX_USER_NAME_LEN);
                }

                if (strncmp (argv[i], "/P=", 3) == 0 || strncmp (argv[i], "/p=", 3) == 0)
                {
                        args--;
                        TrimQuotes (Password, argv[i] + 3, 256);
                }
		
		if (strncmp (argv[i], "/LOG=", 5) == 0 || strncmp (argv[i], "/log=", 5) == 0)
		{
			args--;
			TrimQuotes (Logfile, argv[i] + 5, 256);
		}
		
		if (strncmp (argv[i], "/PAUSE", 6) == 0 || strncmp (argv[i], "/pause", 6) == 0)
		{
			args--;
			Pause = 1;
		}
        }

        return args;
}

/*
 *  GetParam function
 *
 *  retrieves the first "argument" from a string, and returns a pointer to the rest of the string
 *  used to convert a command string into argv, argc, taking account of quotes, and escaped quotes
 *
 */

char* GetParam (char* ParamStr, char* Buffer, int BufferSize)
{
	char* 	SrcPtr;
	char*	DstPtr;
	int	QuoteOpen;

	SrcPtr    = ParamStr;
	DstPtr    = Buffer;
	QuoteOpen = 0;

	// find start of string after leading spaces and leading quotes
	
	while ((*SrcPtr != 0) && (*SrcPtr <= ' ')) SrcPtr++;

	// copy characters from source string until a space or a tab is found, and QuoteOpen is 0
	// also check for space in the buffer
	
	while ((!((*SrcPtr == ' ' || *SrcPtr == '\t') && QuoteOpen == 0)) && (*SrcPtr != 0) && DstPtr < (Buffer + BufferSize))
	{
		// if we find a space, see if its escaped - if it is, then copy it but remove the previous backslash
		// if not then skip it, and invert QuoteOpen
		
		if (*SrcPtr == '"')
		{
			if (SrcPtr > ParamStr)
			{
				if (SrcPtr [-1] == '\\')
				{
					if (DstPtr > Buffer) DstPtr [-1] = '"'; else DstPtr [0] = '"';
				}
				else
				{
					QuoteOpen = !QuoteOpen;
				}
			}
			else
			{
				QuoteOpen = !QuoteOpen;
			}

			SrcPtr++;
		}
		else
		{
			// ignore the end of line character
			
			if (*SrcPtr != '\n')
			{
				*DstPtr = *SrcPtr;
				DstPtr++;
			}
			SrcPtr++;
		}
	}

	// terminate the string in the buffer
	*DstPtr = 0;
	
	// return a pointer to the rest of the string
	return SrcPtr;
}

/*
 *  Restore function
 *
 *  Opens a file stream, and read the file line by line, attempting to read and execute the command like
 *  a bunch of rights commands to restore rights. Useful as it means that the end user doesn't need to login
 *  each like they would if they used an NCF
 *
 */

void Restore (NWCONN_HANDLE ConnHandle, char* FileName, char* Logfilename)
{
	char 		Line 		[1024];
	char* 		Next;
	char 		Buffer 		[512];
	FILE* 		BackupFile;
	FILE*		Logfile;
	char  		FirstParam 	[512];
	char  		Rights 		[12];
	char  		Object 		[300];
	int   		ArgNo;
	char  		Op 		[8];
	NWDSCCODE 	res;
	BYTE 		OldNameSpace;

	// save the default namespace
	OldNameSpace = SetCurrentNameSpace (NW_NS_LONG);

	// attempt to open the backup file
	if ((BackupFile = fopen (FileName, "r")) == NULL)
		printf ("Couldn\'t open file: %s\n", FileName);
	else
	{
		if (Logfilename)
		{
			if ((Logfile = fopen (Logfilename, "w")) == NULL)
			{
				printf ("Couldn't open %s\n", Logfilename);
				Logfile = NULL;
			}
		}
		else
			Logfile = NULL;
		
		// read file line by line - also, check that the NLM hasn't been terminated
		while ((!feof (BackupFile)) && (!NlmExiting))
		{
			fgets (Line, 1024, BackupFile);
			if (!feof (BackupFile))
			{
				Next = Line;
				ArgNo = 0;

				// use GetParams to iteratively get the equivalent argvs
				while (strcmp ((Next = GetParam (Next, Buffer, 512)), "") != 0 || strcmp (Buffer, "") != 0)
				{
					// copy string depending on the argument number
					
					ArgNo++;
					if (ArgNo == 1)
					{
						if (stricmp (Buffer, "RIGHTS") != 0 && stricmp (Buffer, "cx") != 0)
							break;
						else
							strncpy (Op, Buffer, 8);
					}
					
					else if (ArgNo == 2)
						strcpy (FirstParam, Buffer);
					
					else if (ArgNo == 3)
					{
						strncpy (Rights, Buffer, 12);
						Rights [11] = 0;
					}
					
					else if (ArgNo == 4)
					{
						if (strncmp (Buffer, "/NAME=", 6) == 0 || strncmp (Buffer, "/name=", 6) == 0)
							TrimQuotes (Object, Buffer, MAX_DN_CHARS);
						else if (stricmp (Buffer, "/F") == 0)
							strcpy (Object, "/F");
						else
							strcpy (Object, "");
						
					}
					
					else
						break;
				}
				
				// if the syntax is valid call the appropriate function to 
				// set trustee rights or IRFs
				
				if (stricmp (Op, "RIGHTS") ==0 && ArgNo == 4)
				{
					if (strncmp (Object, "/F", 2) == 0 || strncmp (Object, "/f", 2) == 0)
					{
						// printf ("IRF: %s, %s\n", FirstParam, Rights);
						// if (Clear != 0)
						//	InheritedRights (ConnHandle, 0, FirstParam, NW_NS_LONG, "RWCFEMA");
		                                res = InheritedRights (ConnHandle, 0, FirstParam, NW_NS_LONG, Rights);
						DisplayOutput (FirstParam, Rights, "/F", res, Logfile);
					}

					if (strncmp (Object, "/NAME=", 6) == 0 || strncmp (Object, "/name=", 6) == 0)
					{
						// printf ("Rights: %s, %s, %s\n", FirstParam, Rights, Object);
						// if (Clear != 0)
						//	TrusteeRights (ConnHandle, 0, FirstParam, NW_NS_LONG, Object+6, "REM");
	                                        res = TrusteeRights (ConnHandle, 0, FirstParam, NW_NS_LONG, Object+6, Rights);
						DisplayOutput (FirstParam, Rights, Object+6, res, Logfile);
					}
				}

				// code to change context
				if (stricmp (Op, "cx") == 0 && ArgNo == 2)
				{
					if ((res = NWDSSetContext (NDSContext, DCK_NAME_CONTEXT, FirstParam)) != 0)
						printf ("NWDSSetContext returned: %d\n", res);
				}
					
			}
		}
		
		// close the file and restore the original name space
		fclose (BackupFile);
		if (Logfile)
			fclose (Logfile);
		
		SetTargetNameSpace (OldNameSpace);
	}
}

/*
 *  Usage function - displays information on using the NLM
 *
 */

void Usage (void)
{
	clrscr ();
	gotoxy (28, 0);
	printf ("NetWare Rights Utility\n");
	gotoxy (28, 1);
	printf ("(c) 2003  J. Gallimore\n");
	printf ("\n\n");

        printf ("NWRights Usage:\n\n");
        printf ("NWRights <path> [<rights> {/NAME=<NDS object> | /F}] [/U=<user>] [/P=<pass>]\n");
        printf ("NWRights <path> /B=<backup file> [U=<username>] [/P=<password>]\n");
        printf ("NWRights /R=<restore file>\n\n");
        printf ("Rights:\n");
        printf ("\tR - Read\tF - Filescan\tW - Write\t\tM - Modify\n");
        printf ("\tE - Erase\tC - Create\tA - Access Control\tS - Supervisor\n\n");
	printf ("\t+ - Add to existing trustee rights\n");
	printf ("\t- - Revoke from existing trustee rights\n");
	printf ("\tREM - Remove trustee\n\n");
        AutoDestroyScreen = 0x0;
}

/*
 *  Main function
 *
 *  processes the command line arguments, and diverts the NLM off to the right function
 *
 */

int main (int argc, char* argv[])
{
        NWDSCCODE               res;
        nstr8                   UserName   [NW_MAX_USER_NAME_LEN];
        nstr8                   Password   [256];
        nstr8                   Object     [MAX_DN_CHARS+1];
        nstr8                   FileName   [256];
	nstr8			Logfile	   [256];
        nstr8                   ServerName [50];
	NWCONN_HANDLE           ConnHandle;
        FILE*                   BackupFile;
        int                     NonOptArgs;
        BYTE                    OldNameSpace;

        // start off by auto destroying the screen
	AutoDestroyScreen = 0xF;
	
	// increment the thread counter
	ThreadCount++;
	
	// get the main thread group id
	MainThreadGroupId = GetThreadGroupID ();

	// set the signal handler, and disable CTRL-C
	signal (SIGTERM, SigHandler);
	SetCtrlCharCheckMode (FALSE);

	// make sure we've got something to do - i know, this would be more appropriately done in the switch below
	if (argc == 1)
	{
		Usage ();
		return 1;
	}

	clrscr ();
	gotoxy (28, 0);
	printf ("NetWare Rights Utility\n");
	gotoxy (28, 1);
	printf ("(c) 2003  J. Gallimore\n");
	printf ("\n\n");
        
	// create a global context handle
	if ((res = NWDSCreateContextHandle (&NDSContext)) != 0)
        {
                printf ("NWDSCreateContextHandle returned: %d\n", res);
                return 1;
        }

        DoLogin = 0;

        // attempt to retrieve the username and password from the command line
	NonOptArgs = GetOptArgs (argc, argv, UserName, Password, Logfile);

        // login if we need to
	// ask for the username / password, if not specified on the command line
	// if user input is required, don't automatically close the screen
	
	if (!NWIsDSAuthenticated ())
        {
                printf ("Login to NDS\nUsername:");

                if (strcmp (UserName, "") == 0)
       	        {
               	        AutoDestroyScreen = 0x0;
			AwaitingInput = TRUE;
                        gets (UserName);
			AwaitingInput = FALSE;
               	}
                else
       	                printf ("%s\n", UserName);

		// included if the nlm is unloaded whilst inputting details
		if (NlmExiting)
		{
			Cleanup ();
			return 1;
		}

                printf ("Password:");

		if (strcmp (Password, "") == 0)
       	        {
               	        AutoDestroyScreen = 0x0;
			AwaitingInput = TRUE;
                        GetPass (Password, 256);
			AwaitingInput = FALSE;
               	}
                else
       	                printf ("*\n");

		// included if the nlm is unloaded whilst inputting details
		if (NlmExiting)
		{
			Cleanup ();
			return 1;
		}
                
                if ((res = NWDSLogin (NDSContext, 0, UserName, Password, 0)) != 0)
                {
       	                printf ("NWDSLogin returned: %d\n", res);
               	        Cleanup ();
                       	return 1;
		}
                DoLogin = 1; // if we logged in, we must logout
        }

	// included if the nlm is unloaded whilst inputting details
	if (NlmExiting)
	{
		Cleanup ();
		return 1;
	}

        // open and authenticate a connection to the local box	
	GetFileServerName (0, ServerName);

        if ((res = NWCCOpenConnByName (0, ServerName, NWCC_NAME_FORMAT_NDS, NWCC_OPEN_LICENSED, NWCC_RESERVED, &ConnHandle)) != 0)
        {
                printf ("NWDSOpenConnToNDSServer returned: %d\n", res);
                Cleanup ();
                return 1;
        }
        
        if ((res = NWDSAuthenticateConn (NDSContext, ConnHandle)) != 0)
        {
                printf ("NWDSAuthenticateConn returned: %d\n", res);
                Cleanup ();
                return 1;
        }

        // change to the [Root] context
	if ((res = NWDSSetContext (NDSContext, DCK_NAME_CONTEXT, "[Root]")) != 0)
        {
                printf ("NWDSSetContext returned: %d\n", res);
                Cleanup ();
                return 1;
        }

        // process the command line arguments
	switch (NonOptArgs)
        {
                case 0:
                        Usage ();
                break;

                case 1:
                        Usage ();
                break;

                case 2:
                        if (strncmp (argv [1], "/R=", 3) == 0 || strncmp (argv [1], "/r=", 3) == 0)
                        {
                                if (TrimQuotes (FileName, argv [1] + 3, 256) == 0)
                                {
                                        // perform a restore
					Restore (ConnHandle, FileName, Logfile);
                                }
                        }
                        else
                        {
                                // display trustee rights, don't auto close screen
				AutoDestroyScreen = 0x0;
                                GetTrustees (ConnHandle, 0, argv [1], NW_NS_LONG, 1, NULL);
                        }
                break;

                case 3:
                        if (strncmp (argv [2], "/B=", 3) == 0 || strncmp (argv [2], "/b=", 3) == 0)
                        {
                                // backup the trustee rights to a file
				if (TrimQuotes (FileName, argv[2] + 3, 256) == 0)
                                {
                                        OldNameSpace = SetCurrentNameSpace (NW_NS_LONG);
                                        if ((BackupFile = fopen (FileName, "w")) != NULL)
                                        {
                                                fprintf (BackupFile, "cx [Root]\n");
                                                GetTrustees (ConnHandle, 0, argv [1], NW_NS_LONG, 1, BackupFile);
                                                fclose (BackupFile);
                                        }
                                }
                        }
                break;

                case 4:
                        // set trustee rights or IRF as appropriate
		
			if (strncmp ("/F", argv [3], 2) == 0 || strncmp ("/f", argv [3], 2) == 0)
                        {
                                // inherited rights filter
                                InheritedRights (ConnHandle, 0, argv [1], NW_NS_LONG, argv [2]);
                        }

                        if (strncmp (argv[3], "/NAME=", 6) == 0 || strncmp (argv[3], "/name=", 6) == 0)
                        {
                                // get pointer to name, strip off leading and trailing "
                                if (TrimQuotes (Object, argv [3] + 6, MAX_DN_CHARS+1) == 0)
                                        TrusteeRights (ConnHandle, 0, argv [1], NW_NS_LONG, Object, argv [2]);
                        
                        }

                break;

                default:
                        Usage ();
                break;
        }

        // close local connection and cleanup
	if ((res = NWCCCloseConn (ConnHandle)) != 0)
                printf ("NWCCCloseConn returned: %d\n", res);
        
        Cleanup ();
        return 0;               
}

/*
 *  Cleanup function
 *
 *  cleans up global variables
 *
 */

void Cleanup (void)
{
        NWDSCCODE res;

	// set the auto screen destroy mode based on the command line arguments
        SetAutoScreenDestructionMode (AutoDestroyScreen);

	// if we logged in, we should logout
	if (DoLogin == 1)
        
                if ((res = NWDSLogout (NDSContext)) != 0)
                        printf ("NWDSLogout returned: %d\n", res);

	// free the context handle
	if ((res = NWDSFreeContext (NDSContext)) != 0)
                printf ("NWDSFreeContext returned: %d\n", res);

	// decrement the thread counter
	ThreadCount--;
}

/*
 *  SigHandler
 *
 *  Handles NLM termination signals, and persuade the NLM to exit cleanly
 *
 */

void SigHandler (int sig)
{
	int ThreadGroupId;

	switch (sig)
	{
		case SIGTERM:
			
			// tell the NLM its exiting, and save the console threadid, recovering the main threadid
			NlmExiting = TRUE;
			ThreadGroupId = SetThreadGroupID (MainThreadGroupId);

			// if the NLM is waiting on the user, stuff an enter keypress into the keyboard buffer
			if (AwaitingInput)
				ungetch (KEY_ENTER);

			// allow the NLM to finish cleanly			
			while (ThreadCount != 0)
				ThreadSwitchWithDelay ();

			// restore the console threadid
			SetThreadGroupID (ThreadGroupId);
		break;
	}

	return;
}

/*
 * DisplayOutput function
 *
 * Function to display results, with error description if necessary
 *
 */

void DisplayOutput (char* File, char* Rights, char* Trustee, int Errcode, FILE* Logfile)
{
	if (stricmp (Trustee, "/f") == 0)
		printf ("%s\t%s\t%s", File, Rights, Trustee);
	else
		printf ("%s\t%s\t/NAME=%s", File, Rights, Trustee);
	
	if (Logfile)
		fprintf (Logfile, "%s %s %s", File, Rights, Trustee);
	
	switch (Errcode)
	{
		case SUCCESS:
			printf ("\n");
			if (Logfile)
				fprintf (Logfile, "\n");
			break;
		
		case ERR_FILE_INFO:
			printf (" - Error getting file information\n");
			if (Logfile)
				fprintf (Logfile, " - Error getting file information\n");
			break;
			
		case ERR_TRUSTEE_TO_NDS_OBJ:
			printf (" - Error mapping trustee to NDS object\n");
			if (Logfile)
				fprintf (Logfile, " - Error mapping trustee to NDS object\n");
			break;
			
		case ERR_NDS_OBJ_TO_TRUSTEE:
			printf (" - Error mapping NDS object to trustee\n");
			if (Logfile)
				fprintf (Logfile, " - Error mapping NDS object to trustee\n");
			break;
		
		case ERR_CANT_ASSIGN_RIGHTS:
			printf (" - Error assigning rights\n");
			if (Logfile)
				fprintf (Logfile, " - Error assigning rights\n");
			break;
		
		case ERR_CANT_SET_FILTER:
			printf (" - Error setting filter\n");
			if (Logfile)
				fprintf (Logfile, " - Error setting filter\n");
			break;
	}
	
	if (Pause != 0 && wherey () >= 22)
	{
		AwaitingInput = TRUE;
		PressAnyKeyToContinue ();
		AwaitingInput = FALSE;
		clrscr ();
	}
}
