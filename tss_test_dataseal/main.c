#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tspiproglib.h"

int MyFunc_CreatePCRs(TSS_HCONTEXT *context, 
		TSS_HTPM *tpm,
		UINT32 num_PCRs, UINT32 *PCRs, TSS_HPCRS *hPCRs);

int main(){
	TSS_RESULT		res = TSS_SUCCESS;
	TSS_HCONTEXT 	hContext;
	TSS_HTPM 	hTPM = 0;
	TSS_FLAG	initFlags;
	TSS_HKEY	hSRK = 0;
	TSS_HKEY	hKey;
	TSS_UUID	SRK_UUID = TSS_UUID_SRK;
	BYTE		*secret = "111111";
	TSS_HPOLICY		hPolicy;
	
	TSS_HPCRS	hPCRs;
	UINT32		PCR_index[] = {2,3,5};
	UINT32		in_size;
	BYTE		*in = "helloworld";
	UINT32		out_size;
	BYTE		*out;
	TSS_HENCDATA	hEncData;
	UINT32		keySize;
	
	in_size = strlen(in);
	
	
	Tspi_Context_Create(&hContext);
	Tspi_Context_Connect(hContext, NULL);
	Tspi_Context_GetTpmObject(hContext, &hTPM);
	
	Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
	
	Tspi_GetPolicyObject( hSRK, TSS_POLICY_USAGE, &hPolicy );
    Tspi_Policy_SetSecret( hPolicy, TSS_SECRET_MODE_PLAIN,
                           strlen((char*)secret), (BYTE*)secret);
	
	initFlags = TSS_KEY_TYPE_STORAGE | TSS_KEY_SIZE_2048 | 
				TSS_KEY_NO_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE;
				
	Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
				initFlags, &hKey);
				
	Tspi_Key_CreateKey(hKey, hSRK, 0);
	
	// Print all PCRs
	printf("Before Data Sealing.\n\n");
	MyFunc_PrintAllPCRs(&hContext, &hTPM);
	
	//Create the encrypted data object in the TSP
	Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_ENCDATA,
				TSS_ENCDATA_SEAL, &hEncData);
				
	Tspi_GetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
				TSS_TSPATTRIB_KEYINFO_SIZE,
				&keySize);
				
	/* Make sure the data is small enough to be bound by this key, 
	   taking into account the OAEP padding size (38) and the size 
	   of the TPM_SEALED_DATA structure (65). */
	if(in_size > keySize - 103) {
		printf("Data to be encrypted is too big.\n");
		return -1;
	}
	
	/* Load key into TPM before sealing */
	Tspi_Key_LoadKey(hKey, hSRK);
	
	if(MyFunc_CreatePCRs(&hContext, &hTPM, 3, PCR_index, &hPCRs) != 0) {
		printf("MyFunc_CreatePCRs failed.\n");
	}
	
	res = Tspi_Data_Seal(hEncData, hKey, in_size, in, hPCRs);
	if(res != TSS_SUCCESS) {
		printf("Data sealing failed.\n");
		return -1;
	}
	
	//Now hEncData contains an encrypted blob, let's extract it.
	Tspi_GetAttribData(hEncData, TSS_TSPATTRIB_ENCDATA_BLOB,
				TSS_TSPATTRIB_ENCDATABLOB_BLOB,
				&out_size, &out);
				
	// Print all PCRs
	printf("After Data Sealing.\n\n");
	MyFunc_PrintAllPCRs(&hContext, &hTPM);
	
	// Print out buffer
	printf("\"out\" Buffer.\n");
	hex_print((char*)out, out_size);
				
	Tspi_Context_FreeMemory(hContext, out);
	Tspi_Context_CloseObject(hContext, hEncData);
	Tspi_Context_Close(hContext);
	
	return 0;
}

int MyFunc_CreatePCRs(TSS_HCONTEXT *context, 
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






