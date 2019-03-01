#include <iostream>
#include <string>
#include <string.h>
#include <stdlib.h>

extern "C" {
	#include "tpm_tspi.h"
	#include "tpm_utils.h"
	//#include "tspiproglib.h"
	#include <openssl/rsa.h>
	#include <tcg/include/common.h>
}

#define MY_UUID_AIK {0,0,0,0,0,{'M','Y','_','A','I','K'}}

int main() {
	TSS_RESULT		res = TSS_SUCCESS;
	TSS_HCONTEXT 	hContext;
	TSS_HTPM 	hTPM = 0;
	TSS_HKEY	hSRK = 0;
	TSS_HKEY	hAIKey = 0;
	TSS_UUID	SRK_UUID = TSS_UUID_SRK;
	BYTE		*secret = (BYTE*)"111111";
	TSS_HPOLICY		hPolicy, hTPMPolicy;
	TSS_HPOLICY		hAIKPolicy;
	BYTE *AIKPub = NULL;
	UINT32 AIKPubLen = 0;
	TSS_UUID AIK_UUID = MY_UUID_AIK;
	TSS_FLAG AIKInitFlags	= TSS_KEY_TYPE_IDENTITY | TSS_KEY_SIZE_2048  |
			TSS_KEY_VOLATILE | TSS_KEY_NO_AUTHORIZATION |
			TSS_KEY_NOT_MIGRATABLE;

	//Create Context
	res = connect_load_all(&hContext, &hSRK, &hTPM);
	if (res != TSS_SUCCESS) {
		print_error("connect_load_all", res);
		exit(res);
	}	

	//Create Identity Key Object
	res = Tspi_Context_CreateObject(hContext,
					   TSS_OBJECT_TYPE_RSAKEY,
					   AIKInitFlags, &hAIKey);
	if(res != TSS_SUCCESS) {
		print_error("CreateObject loadedAIK failed.", res);
		goto END;
	}

	res = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_USER, AIK_UUID, &hAIKey);
	if(res != TSS_SUCCESS){
		print_error("LoadKeyByUUID: failed.",res);
		goto END;
	}

	//	res = GetPubKey(&hAIKey, &hSRK, &AIKPubLen, &AIKPub);
	res = keyGetPubKey(hAIKey, &AIKPubLen, &AIKPub);
	if(res != TSS_SUCCESS){
		print_error("GetPubKey: getting public part of hAIKey failed", res);
		goto END;
	}
	
	std::cout<< "Display Loaded PubAIK" << std::endl;
	displayKey(hAIKey);
	Tspi_Context_FreeMemory(hContext, AIKPub);
	
END:
	Tspi_Context_FreeMemory(hContext, NULL);
	Tspi_Context_Close(hContext);

	return 0;
}
