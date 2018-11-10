#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tspiproglib.h"

int		MyFunc_CreateTPMKey(TSS_HCONTEXT *context, TSS_HKEY *srk, TSS_HKEY *tpm_key){
    TSS_FLAG nFlags = 0;
    TSS_RESULT res = TSS_SUCCESS;

    if(context == NULL || srk == NULL || tpm_key == NULL) {
        printf("MyFunc_CreateTPMKey: none of the parameters can be null.\n");
        return -1;
    }

    nFlags = TSS_KEY_TYPE_BIND | TSS_KEY_SIZE_512 |
             TSS_KEY_NO_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE;

    res = Tspi_Context_CreateObject(*context, TSS_OBJECT_TYPE_RSAKEY, nFlags, tpm_key);
    if(res != TSS_SUCCESS) {
        printf("MyFunc_CreateTPMKey: create tpm_key failed.\n");
        return -1;
    }

    res = Tspi_SetAttribUint32(*tpm_key, TSS_TSPATTRIB_KEY_INFO,
                               TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
                               TSS_ES_RSAESPKCSV15);
    if(res != TSS_SUCCESS) {
        printf("MyFunc_CreateTPMKey: set attribute failed.\n");
        return -1;
    }

    res = Tspi_Key_CreateKey(*tpm_key, *srk, 0);
    if(res != TSS_SUCCESS){
        printf("MyFunc_CreateTPMKey: create tpm key failed.\n");
        return -1;
    }

    return 0;
}

int		MyFunc_DataBinding(TSS_HCONTEXT *context, UINT32 in_size, BYTE *in,
                              UINT32 *out_size, BYTE *out, TSS_HKEY *tpm_key) {
    TSS_HENCDATA hEncData;
    UINT32 keysize, tmp_out_size;
    BYTE* tmp_out = NULL;
    TSS_RESULT res = TPM_SUCCESS;

    if(in == NULL || in_size == 0|| out == NULL || tpm_key == NULL) {
        printf("MyFunc_DataBinding: incorrect parameters.\n");
        return -1;
    }

    res = Tspi_Context_CreateObject(*context, TSS_OBJECT_TYPE_ENCDATA,
                                    TSS_ENCDATA_BIND, &hEncData);
    if(res != TSS_SUCCESS) {
        printf("MyFunc_DataBinding: create EncData object failed.\n");
        return -1;
    }

    //Get key size
    res = Tspi_GetAttribUint32(*tpm_key, TSS_TSPATTRIB_KEY_INFO,
                               TSS_TSPATTRIB_KEYINFO_SIZE, &keysize);
    if(res != TSS_SUCCESS){
        printf("MyFunc_DataBinding: get key size failed.\n");
        return -1;
    }

    /* Make sure the data size is enough to be bound by this key,
       taking into account the PKCS#1v1.
       padding size (11) and the size of the TPM_BOUND_DATA
       structure (5) */
    if (in_size > keysize - 16) {
        printf("Data to be encrypted is too big. exiting...\n");
        return -1;
    }

    res = Tspi_Data_Bind(hEncData, *tpm_key, in_size, in);
    if(res != TSS_SUCCESS){
        printf("MyFunc_DataBinding: data bind failed.\n");
        return -1;
    }

    //Extract the encrypted data from hEncData
    res = Tspi_GetAttribData(hEncData, TSS_TSPATTRIB_ENCDATA_BLOB,
                             TSS_TSPATTRIB_ENCDATABLOB_BLOB, &tmp_out_size, &tmp_out);
    if(res != TSS_SUCCESS){
        printf("MyFunc_DataBinding: get encrypted data failed.\n");
        return -1;
    }

    if(tmp_out_size > *out_size) {
        printf("Encrypted data blob is too big.\n");
        return -1;
    }

    //Copy the encrypted data blob to the user's buffer
    memcpy(out, tmp_out, tmp_out_size);
    *out_size = tmp_out_size;

    //Free encrypted blob memory
    Tspi_Context_FreeMemory(*context, tmp_out);

    //Close encrypted data object
    Tspi_Context_CloseObject(*context, hEncData);

    return 0;
}

int     MyFunc_DataUnbinding(TSS_HCONTEXT *context, TSS_HKEY *tpm_key,
        UINT32 in_size, BYTE* in,
        UINT32 *unbind_data_size, BYTE** unbind_data) {
    TSS_RESULT res = TSS_SUCCESS;
    TSS_HENCDATA hEncData;
    TSS_UUID SRK_UUID = TSS_UUID_SRK;
    TSS_HKEY hSRK;

    if(context == NULL || tpm_key == NULL ||
        in == NULL || in_size <= 0 ||
        unbind_data == NULL || unbind_data_size <= 0){
        printf("MyFunc_DataUnbinding: incorrect parameters.\n");
        return -1;
    }

    res = Tspi_Context_CreateObject(*context,TSS_OBJECT_TYPE_ENCDATA,
                              TSS_ENCDATA_BIND,&hEncData);
    if(res != TSS_SUCCESS){
        printf("MyFunc_DataUnbinding: create object hEncData failed.\n");
        return -1;
    }

    res = Tspi_SetAttribData(hEncData,TSS_TSPATTRIB_ENCDATA_BLOB,
                       TSS_TSPATTRIB_ENCDATABLOB_BLOB,in_size,in);
    if(res != TSS_SUCCESS){
        printf("MyFunc_DataUnbinding: set attribute failed.\n");
        return -1;
    }

    //IMPORTANT!
    //tpm_key must be reloaded in to TPM,
    //otherwise the Tspi_Data_Unbind would return error 0x310E (TSS_E_KEY_NOT_LOADED)
    Tspi_Context_LoadKeyByUUID(*context, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
    Tspi_Key_LoadKey(*tpm_key, hSRK);

    res = Tspi_Data_Unbind(hEncData, *tpm_key, unbind_data_size, unbind_data);
    if(res != TSS_SUCCESS){
        printf("MyFunc_DataUnbinding: data unbinding failed. Error No.: 0x%010x\n", ERROR_CODE(res));

        printf("ERROR_LAYER: %x\n", ERROR_LAYER(res));
        printf("TSP ERROR: %x\n", TSP_ERROR(res));
        if(ERROR_CODE(res) == TSS_E_INTERNAL_ERROR)
            printf("TSS_E_INTERNAL_ERROR\n");

        return -1;
    }

    Tspi_Context_CloseObject(*context, hEncData);

    return 0;
}

void	hex_print(char* data, int length)
{
    int ptr = 0;
    for(;ptr < length;ptr++)
    {
        printf("0x%02x ",(unsigned char)*(data+ptr));
    }
    printf("\n");
}