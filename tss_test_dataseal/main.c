#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tspiproglib.h"

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










