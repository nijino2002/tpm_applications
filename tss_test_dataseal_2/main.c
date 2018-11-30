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
	UINT32		PCR_index[] = {2,3,5};
	UINT32		in_size;
	BYTE		*in = "helloworld";
	UINT32		out_size;
	BYTE		*out = NULL;
	
	in_size = strlen(in);
	
	
	Tspi_Context_Create(&hContext);
	Tspi_Context_Connect(hContext, NULL);
	Tspi_Context_GetTpmObject(hContext, &hTPM);
	
	Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
	
	Tspi_GetPolicyObject( hSRK, TSS_POLICY_USAGE, &hPolicy );
    Tspi_Policy_SetSecret( hPolicy, TSS_SECRET_MODE_PLAIN,
                           strlen((char*)secret), (BYTE*)secret);
	
	//Create TPM key
	initFlags = TSS_KEY_TYPE_STORAGE | TSS_KEY_SIZE_2048 | 
				TSS_KEY_NO_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE;
				
	Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
				initFlags, &hKey);
				
	Tspi_Key_CreateKey(hKey, hSRK, 0);
	
	// Print all PCRs
	printf("Before Data Sealing.\n\n");
	MyFunc_PrintAllPCRs(&hContext, &hTPM);
	
	MyFunc_CreatePCRs(&hContext, &hTPM, 3, PCR_index, &hPCRs);
	if(MyFunc_DataSeal(&hContext, &hTPM, &hKey, in_size, in, &out_size, &out, &hPCRs) != 0){
		printf("MyFunc_DataSeal failed.\n");
		goto LABEL_FINISH;
	}
	
	// Print all PCRs
	printf("After Data Sealing.\n\n");
	MyFunc_PrintAllPCRs(&hContext, &hTPM);				
	
	// Print out buffer
	printf("\"out\" Buffer.\n");
	hex_print((char*)out, out_size);
	free(out);
	
LABEL_FINISH:			
	Tspi_Context_Close(hContext);
	
	return 0;
}






