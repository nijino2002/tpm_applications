#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tspiproglib.h"

int main() {
    TSS_HCONTEXT	hContext;
    TSS_HTPM		hTPM;
    TSS_HKEY		hSRK, hTPMKey;
    BYTE			*secret = (BYTE*)"111111";
    TSS_HPOLICY		hPolicy;
    TSS_UUID	SRK_UUID = TSS_UUID_SRK;
    TSS_RESULT		res = TSS_SUCCESS;
    UINT32 uPCRLen = 0;
    BYTE* rgbPCRValue;
    UINT32 extValLen = 0;
    //must be 20 bytes!!
    BYTE* extVal = "abcdefghijklmnopqrst";

    Tspi_Context_Create(&hContext);
    Tspi_Context_Connect(hContext, NULL);
    Tspi_Context_GetTpmObject(hContext, &hTPM);

    res = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM,
                                     SRK_UUID, &hSRK);
    if(res != TSS_SUCCESS) {
        printf("Error occured in Tspi_Context_LoadKeyByUUID.\n");
        exit(1);
    }

    Tspi_GetPolicyObject( hSRK, TSS_POLICY_USAGE, &hPolicy );
    Tspi_Policy_SetSecret( hPolicy, TSS_SECRET_MODE_PLAIN,
                           strlen((char*)secret), (BYTE*)secret);

    //Output the values of all the PCRs
    MyFunc_PrintAllPCRs(&hContext, &hTPM);
    //Change PCR 0
    MyFunc_ExtendPCR(&hContext, &hTPM, 0, strlen(extVal), extVal, &uPCRLen, &rgbPCRValue);
    printf("VAL_LEN: %d, VALUE: 0x%02x\n", uPCRLen, *rgbPCRValue);
    Tspi_Context_FreeMemory(hContext, rgbPCRValue);

    MyFunc_PrintAllPCRs(&hContext, &hTPM);

    Tspi_Context_FreeMemory(hContext, NULL);
    Tspi_Context_Close(hContext);

    return 0;
}