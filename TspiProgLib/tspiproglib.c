#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tspiproglib.h"

int 	MyFunc_Init(TSS_HCONTEXT *context, TSS_HTPM *tpm, BYTE *secret) {
	TSS_RESULT 		res = TSS_SUCCESS;
	TSS_HPOLICY 	hPolicy;
	TSS_HKEY 		hSRK = 0;
	TSS_UUID		SRK_UUID = TSS_UUID_SRK;
	
	if(context == NULL || tpm == NULL || secret == NULL) {
		printf("MyFunc_Init: incorrect parameters.\n");
		return -1;
	}
	
	Tspi_Context_Create(context);
	Tspi_Context_Connect(*context, NULL);
	Tspi_Context_GetTpmObject(*context, tpm);
	
	Tspi_Context_LoadKeyByUUID(*context, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
	
	Tspi_GetPolicyObject( hSRK, TSS_POLICY_USAGE, &hPolicy );
    Tspi_Policy_SetSecret( hPolicy, TSS_SECRET_MODE_PLAIN,
                           strlen((char*)secret), (BYTE*)secret);
                           
	return 0;
}

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

int		MyFunc_CreateTPMKey2(TSS_HCONTEXT *context, TSS_HKEY *srk, TSS_HKEY *tpm_key, TSS_FLAG key_flags) {
	TSS_FLAG nFlags = key_flags;
    TSS_RESULT res = TSS_SUCCESS;

    if(context == NULL || srk == NULL || tpm_key == NULL) {
        printf("MyFunc_CreateTPMKey: none of the parameters can be null.\n");
        return -1;
    }

    nFlags = TSS_KEY_TYPE_BIND | TSS_KEY_SIZE_512 |
             TSS_KEY_NO_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE;

    res = Tspi_Context_CreateObject(*context, TSS_OBJECT_TYPE_RSAKEY, nFlags, tpm_key);
    if(res != TSS_SUCCESS) {
        printf("MyFunc_CreateTPMKey2: create tpm_key failed.\n");
        return -1;
    }

    res = Tspi_SetAttribUint32(*tpm_key, TSS_TSPATTRIB_KEY_INFO,
                               TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
                               TSS_ES_RSAESPKCSV15);
    if(res != TSS_SUCCESS) {
        printf("MyFunc_CreateTPMKey2: set attribute failed.\n");
        return -1;
    }

    res = Tspi_Key_CreateKey(*tpm_key, *srk, 0);
    if(res != TSS_SUCCESS){
        printf("MyFunc_CreateTPMKey2: create tpm key failed.\n");
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

void	char_print(char* data, int length) {
	int ptr = 0;
    for(;ptr < length;ptr++)
    {
        printf("%c",(unsigned char)*(data+ptr));
    }
    printf("\n");
}

int MyFunc_PrintAllPCRs(TSS_HCONTEXT *context, TSS_HTPM *tpm) {
    TSS_RESULT res = TSS_SUCCESS;
    UINT32 uPCRLen;
    BYTE*  rgbPCRValue = NULL;
    int i,j;

    if(context == NULL || tpm == NULL) {
        printf("MyFunc_PrintAllPCRs: incorrect parameters.\n");
        return -1;
    }

    for(i=0; i<24; i++){
        res = Tspi_TPM_PcrRead(*tpm, i, &uPCRLen, &rgbPCRValue);
        if(res != TSS_SUCCESS){
            printf("MyFunc_PrintAllPCRs: Read PCR %d error.\n", i);
            return -1;
        }
        printf("PCR %02d: ", i);
        for (j=0; j<19; j++) {
            printf("%02x ", *(rgbPCRValue+j));
        }
        printf("\n");
    }

    Tspi_Context_FreeMemory(*context, rgbPCRValue);
    return 0;
}

int     MyFunc_ExtendPCR(TSS_HCONTEXT *context, TSS_HTPM *tpm, UINT32 pcr_index,
                         UINT32 in_size, BYTE* in,
                         UINT32 *out_size, BYTE** out){
    TSS_RESULT res = TSS_SUCCESS;

    if(context == NULL || tpm == NULL || in_size != 20 || in == NULL) {
        printf("MyFunc_ExtendPCR: incorrect parameters.\n");
        return -1;
    }

    if(pcr_index < 0 || pcr_index > 23) {
        printf("MyFunc_ExtendPCR: invalid PCR index.\n");
        return -1;
    }

    res = Tspi_TPM_PcrExtend(*tpm, pcr_index, in_size, in, NULL, out_size, out);
    if(res != TSS_SUCCESS) {
        printf("MyFunc_ExtendPCR: Tspi_TPM_PcrExtend failed.\n");
        return -1;
    }

    return 0;
}

int     MyFunc_ReadPCR(TSS_HCONTEXT *context, TSS_HTPM *tpm, UINT32 pcr_index, 
						UINT32 *out_size, BYTE **out) {
	TSS_RESULT res = TSS_SUCCESS;
    UINT32 uPCRLen;
    BYTE*  rgbPCRValue = NULL;
    
	if(context == NULL || tpm == NULL || out_size == NULL) {
		printf("MyFunc_ReadPCR: incorrect parameters.\n");
		return -1;
	}
	
	if(pcr_index < 0 || pcr_index > 23) {
        printf("MyFunc_ReadPCR: invalid PCR index.\n");
        return -1;
    }
    
    res = Tspi_TPM_PcrRead(*tpm, pcr_index, &uPCRLen, &rgbPCRValue);
    
    *out_size = uPCRLen;
    memcpy(*out, rgbPCRValue, uPCRLen);
    
    Tspi_Context_FreeMemory(*context, rgbPCRValue);
	return 0;
}

int	MyFunc_CreatePCRs(TSS_HCONTEXT *context, 
		TSS_HTPM *tpm,
		UINT32 num_PCRs, 	// the number of specified PCRs
		UINT32 *PCRs, //indices of specified PCRs
		TSS_HPCRS *hPCRs) {
	UINT32 numPCRs, subCap, i;
	UINT32 ulPCRValueLength;
	BYTE *rgbPCRValue, *rgbNumPCRs;
	
	Tspi_Context_CreateObject(*context, TSS_OBJECT_TYPE_PCRS, 0, hPCRs);
	
	//Retrieve number of PCRs from the TPM
	subCap = TSS_TPMCAP_PROP_PCR;
	Tspi_TPM_GetCapability(*tpm, TSS_TPMCAP_PROPERTY,
			sizeof(UINT32), (BYTE*)&subCap,
			&ulPCRValueLength, &rgbNumPCRs);
			
	numPCRs = *(UINT32*)rgbNumPCRs;
	Tspi_Context_FreeMemory(*context, rgbNumPCRs);
	
	for(i = 0; i < num_PCRs; i++) {
		if(PCRs[i] >= numPCRs) {
			printf("MyFunc_CreatePCRs: PCR %d's value %u is too big.\n", i, PCRs[i]);
			Tspi_Context_CloseObject(*context, *hPCRs);
			return -1;
		}
		
		Tspi_TPM_PcrRead(*tpm, PCRs[i], &ulPCRValueLength, &rgbPCRValue);
		
		Tspi_PcrComposite_SetPcrValue(*hPCRs, PCRs[i], ulPCRValueLength, rgbPCRValue);
		
		Tspi_Context_FreeMemory(*context, rgbPCRValue);
	}
	
	return 0;
}

int     MyFunc_DataSeal(TSS_HCONTEXT *context, TSS_HTPM *tpm, TSS_HKEY *key, 
						UINT32 in_size, BYTE *in,
                        UINT32 *out_size, BYTE **out,
                        TSS_HPCRS *pcrs) {
	TSS_RESULT res = TSS_SUCCESS;
	TSS_HENCDATA	hEncData;
	TSS_UUID SRK_UUID = TSS_UUID_SRK;
    TSS_HKEY hSRK;
    UINT32	keySize = 0;
    UINT32	tmp_out_size = 0;
    BYTE	*tmp_out = NULL;
	
	if(context == NULL || tpm == NULL || key == NULL) {
		printf("MyFunc_DataSeal: Incorrect parameters.\n");
		return -1;
	}
	
	if(in_size == 0 || in == NULL) {
		printf("MyFunc_DataSeal: in_size must bigger than 0 and in must be non-null.\n");
		return -1;
	}
	
	if(*out != NULL) {
		printf("MyFunc_DataSeal: out must be NULL, which will be allocated automatically.\n");
		return -1;
	}
	
	//Load SRK
	Tspi_Context_LoadKeyByUUID(*context, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
	
	//Create the encrypted data object in the TSP
	Tspi_Context_CreateObject(*context, TSS_OBJECT_TYPE_ENCDATA,
				TSS_ENCDATA_SEAL, &hEncData);
	
	//Get key size
	Tspi_GetAttribUint32(*key, TSS_TSPATTRIB_KEY_INFO,
				TSS_TSPATTRIB_KEYINFO_SIZE,
				&keySize);
				
	//Firstly, check key size
	/* Make sure the data is small enough to be bound by this key, 
	   taking into account the OAEP padding size (38) and the size 
	   of the TPM_SEALED_DATA structure (65). */
	if(in_size > keySize - 103) {
		printf("MyFunc_DataSeal: Data to be encrypted is too big.\n");
		return -1;
	}
	
	//key MUST be loaded in TPM
    Tspi_Key_LoadKey(*key, hSRK);
    
    //Seal data
    res = Tspi_Data_Seal(hEncData, *key, in_size, in, *pcrs);
	if(res != TSS_SUCCESS) {
		printf("MyFunc_DataSeal: Data sealing failed.\n");
		return -1;
	}
	
	//Now hEncData contains an encrypted blob, let's extract it.
	Tspi_GetAttribData(hEncData, TSS_TSPATTRIB_ENCDATA_BLOB,
				TSS_TSPATTRIB_ENCDATABLOB_BLOB,
				&tmp_out_size, &tmp_out);
    
    //Allocate memory for "out"
    *out = (BYTE*) malloc (sizeof(BYTE) * tmp_out_size + 1);
    if(*out == NULL) {
    	printf("MyFunc_DataSeal: allocating memory for out buffer failed.\n");
		return -1;
    }
    memset(*out, '\0', sizeof(BYTE) * tmp_out_size + 1);
    memcpy(*out, tmp_out, tmp_out_size);
    *out_size = tmp_out_size;
    
    Tspi_Context_FreeMemory(*context, tmp_out);
	Tspi_Context_CloseObject(*context, hEncData);
    
    return 0;
}

int     MyFunc_DataUnseal(TSS_HCONTEXT *context, TSS_HKEY *tpm_key, 
						UINT32 in_size, BYTE *in,
						UINT32 *unsealed_data_size, BYTE **unsealed_data) {
	TSS_RESULT res = TSS_SUCCESS;
    TSS_HENCDATA hEncData;
    TSS_UUID SRK_UUID = TSS_UUID_SRK;
    TSS_HKEY hSRK;
    
    if(context == NULL || tpm_key == NULL ||
        in == NULL || in_size <= 0 || unsealed_data_size <= 0){
        printf("MyFunc_DataUnseal: incorrect parameters.\n");
        return -1;
    }
    
    if(*unsealed_data != NULL) {
    	printf("MyFunc_DataUnseal: unsealed_data must be NULL, which will be allocated automatically.\n");
        return -1;
    }

    res = Tspi_Context_CreateObject(*context,TSS_OBJECT_TYPE_ENCDATA,
                              TSS_ENCDATA_SEAL, &hEncData);
    if(res != TSS_SUCCESS){
        printf("MyFunc_DataUnseal: create object hEncData failed.\n");
        return -1;
    }

    res = Tspi_SetAttribData(hEncData,TSS_TSPATTRIB_ENCDATA_BLOB,
                       TSS_TSPATTRIB_ENCDATABLOB_BLOB,in_size,in);
    if(res != TSS_SUCCESS){
        printf("MyFunc_DataUnseal: set attribute failed.\n");
        return -1;
    }

    //IMPORTANT!
    //tpm_key must be reloaded in to TPM,
    //otherwise the Tspi_Data_Unbind would return error 0x310E (TSS_E_KEY_NOT_LOADED)
    Tspi_Context_LoadKeyByUUID(*context, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
    Tspi_Key_LoadKey(*tpm_key, hSRK);
    
    res = Tspi_Data_Unseal(hEncData, *tpm_key, unsealed_data_size, unsealed_data);
    if(res != TSS_SUCCESS){
        printf("MyFunc_DataUnseal: data unsealing failed. Error No.: 0x%010x\n", ERROR_CODE(res));

        printf("ERROR_LAYER: %x\n", ERROR_LAYER(res));
        printf("TSP ERROR: %x\n", TSP_ERROR(res));
        if(ERROR_CODE(res) == TSS_E_INTERNAL_ERROR)
            printf("TSS_E_INTERNAL_ERROR\n");

        return -1;
    }
    
    Tspi_Context_CloseObject(*context, hEncData);
    
    return 0;
}





