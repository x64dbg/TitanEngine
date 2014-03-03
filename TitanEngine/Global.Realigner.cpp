#include "stdafx.h"
#include "Global.Realigner.h"

// Global.Realigner.functions:
void SetOverallFileStatus(PFILE_STATUS_INFO myFileInfo, BYTE FiledStatus, bool FiledCritical)
{

    if(myFileInfo->OveralEvaluation == UE_RESULT_FILE_OK || myFileInfo->OveralEvaluation == UE_RESULT_FILE_INVALID_BUT_FIXABLE)
    {
        if(FiledStatus == UE_FIELD_FIXABLE_CRITICAL || FiledStatus == UE_FIELD_BROKEN_FIXABLE_FOR_STATIC_USE || FiledStatus == UE_FIELD_BROKEN_BUT_CAN_BE_EMULATED)
        {
            myFileInfo->OveralEvaluation = UE_RESULT_FILE_INVALID_BUT_FIXABLE;
        }
        else if(FiledStatus == UE_FIELD_BROKEN_NON_FIXABLE && FiledCritical == true)
        {
            myFileInfo->OveralEvaluation = UE_RESULT_FILE_INVALID_AND_NON_FIXABLE;
        }
        else if(FiledStatus == UE_FIELD_BROKEN_FIXABLE_FOR_STATIC_USE)
        {
            myFileInfo->OveralEvaluation = UE_RESULT_FILE_INVALID_BUT_FIXABLE;
        }
    }
}