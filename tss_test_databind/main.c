#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tspiproglib.h"

int main() {
    TSS_HCONTEXT	hContext;
    TSS_HTPM		hTPM;
    TSS_HKEY		hSRK, hTPMKey;
    BYTE			*secret = "111111";
    BYTE			*data = "my data";
    BYTE			enc_data[512] = {0};
    int				enc_data_size = 512;
    BYTE*            decrypt_data;
    UINT32           decrypt_data_size = 0;
    TSS_HPOLICY		hPolicy;
    TSS_UUID	SRK_UUID = TSS_UUID_SRK;
    TSS_RESULT		res = TSS_SUCCESS;

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

    if(MyFunc_CreateTPMKey(&hContext, &hSRK, &hTPMKey) != 0) {
        goto LABEL_FINISH;
    }

    printf("%s\n", data);

    if (MyFunc_DataBinding(&hContext, strlen(data), data, &enc_data_size, enc_data, &hTPMKey) != 0) {
        goto LABEL_FINISH;
    }

    hex_print(enc_data, enc_data_size);

    //Unbinding data
    if(MyFunc_DataUnbinding(&hContext, &hTPMKey,
            enc_data_size, enc_data,
            &decrypt_data_size, &decrypt_data) != 0){
        goto LABEL_FINISH;
    }

    printf("%s\n", decrypt_data);

    LABEL_FINISH:Tspi_Context_FreeMemory(hContext, NULL);

    Tspi_Context_Close(hContext);
}