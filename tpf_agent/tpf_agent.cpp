#include <iostream>
#include <string>
#include <string.h>
#include <stdlib.h>

extern "C" {
	#include "tpm_tspi.h"
	#include "tpm_utils.h"
	#include "tspiproglib.h"
}

int main(int argc, char *argv[]) {
	TSS_RESULT		res = TSS_SUCCESS;
	TSS_HCONTEXT 	hContext;
	TSS_HTPM 	hTPM = 0;
	TSS_FLAG	initFlags;
	TSS_HKEY	hSRK = 0;
	TSS_HKEY	hAIKey;
	TSS_UUID	SRK_UUID = TSS_UUID_SRK;
	BYTE		*secret = (BYTE*)"111111";
	TSS_HPOLICY		hPolicy, hTPMPolicy;
	TSS_HPOLICY		hAIKPolicy;
	BYTE *AIKPub = NULL;
	UINT32 AIKPubLen = 0;
	UINT32 EK_CERT_NV_INDEX = TPM_NV_INDEX_EKCert;
	TSS_HKEY	hEK;
	BYTE bSecret[32] = {0};
	UINT32 uiSecret = 0;
	
	Tspi_Context_Create(&hContext);
	Tspi_Context_Connect(hContext, NULL);
	Tspi_Context_GetTpmObject(hContext, &hTPM);
	
	Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
	
	Tspi_GetPolicyObject( hSRK, TSS_POLICY_USAGE, &hPolicy );
    Tspi_Policy_SetSecret( hPolicy, TSS_SECRET_MODE_PLAIN,
                           strlen((char*)secret), (BYTE*)secret);
                           
        //Get public endorsement key
        res = Tspi_TPM_GetPubEndorsementKey(hTPM, FALSE, NULL, &hEK);
        if (res != TSS_SUCCESS) {
        	std::cout << "Tspi_TPM_GetPubEndorsementKey failed." << std::endl;
        	std::cout << Trspi_Error_String(res) << std::endl;
        	if(ERROR_CODE(res) == TPM_E_DISABLED_CMD) {
        		std::cout << "Enter owner password: ";
        		std::cin >> bSecret;
        		uiSecret = strlen((char*)bSecret);
        		if(uiSecret <= 0) {
        			std::cout << "Owner password cannot be NULL." << std::endl;
        			goto END;
        		}
        		
        		if(!bSecret) {
        			std::cout << "Incorrect owner password." << std::endl;
        			goto END;
        		}
        		Tspi_GetPolicyObject( hTPM, TSS_POLICY_USAGE, &hTPMPolicy );
        		Tspi_Policy_SetSecret( hTPMPolicy, TSS_SECRET_MODE_PLAIN,
                           uiSecret, bSecret);
        		res = Tspi_TPM_GetPubEndorsementKey(hTPM, TRUE, NULL, &hEK);
        		if(res != TSS_SUCCESS){
        			std::cout << "Failed to get public endorsement key." << std::endl;
        			std::cout << Trspi_Error_String(res) << std::endl;
        			goto END;
        		}
        		displayKey(hEK);
        	}
        }//if
	
	//Create TPM key
	initFlags = TSS_KEY_TYPE_IDENTITY | TSS_KEY_SIZE_2048 | TSS_KEY_VOLATILE | 
				TSS_KEY_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE;
				
	res = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
				initFlags, &hAIKey);
	if(res != TSS_SUCCESS) {
		std::cout << "Tspi_Context_CreateObject failed!" << std::endl;
		exit(1);
	}
	
	res = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE,
						&hAIKPolicy);
	if(res != TSS_SUCCESS) {
		std::cout << "Tspi_Context_CreateObject hAIKPolicy failed!" << std::endl;
		exit(1);
	}
	
	res = Tspi_Policy_AssignToObject(hAIKPolicy, hAIKey);
	if(res != TSS_SUCCESS) {
		std::cout << "Tspi_Policy_AssignToObject: hAIKPolicy to hAIKey failed!" << std::endl;
		exit(1);
	}
	
	res = Tspi_Policy_SetSecret(hAIKPolicy, TSS_SECRET_MODE_PLAIN,
						strlen((char*)secret), (BYTE*)secret);
	if(res != TSS_SUCCESS) {
		std::cout << "Tspi_Policy_SetSecret: hAIKPolicy failed!" << std::endl;
		exit(1);
	}
	
	res = Tspi_Key_LoadKey (hAIKey, hSRK);
	if (res != TSS_SUCCESS) {
		std::cout << "Tspi_Key_LoadKey: hAIKey, hSRK failed." << std::endl;
		std::cout << Trspi_Error_String(res) << std::endl;
		exit(1);
	}
	
	res = Tspi_Key_GetPubKey(hAIKey, &AIKPubLen, &AIKPub);
	if(res != TSS_SUCCESS) {
		std::cout << "Tspi_Key_GetPubKey hAIKey failed!" << std::endl;
		std::cout << Trspi_Error_String(res) << std::endl;
		exit(1);
	}
	
	std::cout << "Create AIK successfully." << std::endl;
	
END:
	Tspi_Context_FreeMemory(hContext, NULL);
	Tspi_Context_Close(hContext);
	
	return 0;
}
