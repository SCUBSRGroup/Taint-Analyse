#ifndef __IMAGE_H__
#define __IMAGE_H__
#include "struct.h"
#include "klist.h"
#include "common.h"
#include <string.h>
#define KIEXCEPTION "KiUserExceptionDispatcher"  //代表了KiUserExceptionDispatcher这个API函数
#define GETPROCADDRESS "GetProcAddress"
//extern KList *ImageList;
extern ADDRINT KiUserExceptionDispatcher_Address;
extern REG RegStack;
extern FILE *flog;
extern bool IsAdeobeOrIE;
extern PIN_LOCK WriteFilelock;
extern std::map<int, IMAGEINFO*> g_ModuleInfo;
extern SqQueue *queueInst;
BOOL _IsSystemDll(string img_name);
VOID ImageLoad(IMG img, VOID *v);
VOID _Image_Unload(IMG img,VOID *v);
//UINT32 _GetImageIATcount(BYTE *LoadAddress,BYTE **addressIAT,UINT32 *_ImportIATReal);
//VOID _GetImageFunction(BYTE *addressIAT,UINT32 count,UINT32 *Func);
bool InsertKiUserExceptionDispatcher(IMG img,string modulename);
VOID CheckSafeRET(THREADID id,CONTEXT *ctxt);
VOID CheckSafeSEH(THREADID id,CONTEXT *ctxt);
bool InsertGetProcAddress(IMG img,string imgname);
bool InsertKiUserExceptionDispatcher(IMG img,string modulename);
int comparefunc(VOID *data,VOID *user_data);
#endif

