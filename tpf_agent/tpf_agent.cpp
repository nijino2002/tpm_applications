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

void GetPubEK(TSS_HTPM *hTPM);

TSS_RESULT CreateAIK(TSS_HCONTEXT *hContext, TSS_HTPM *hTPM, TSS_HKEY *hSRK) {
	TSS_RESULT res = TSS_SUCCESS;
	TSS_HKEY hWrappingKey, hSigningKey;

	res = Testsuite_Transport_Init(*hContext, *hSRK, *hTPM, TRUE, FALSE, &hWrappingKey, &hSigningKey);
	if(res != TSS_SUCCESS){
		print_error("Testsuite_Transport_Init failed.", res);
		return res;
	}

	return res;
}

void GetPubEK(TSS_HTPM *hTPM){
	TSS_RESULT res = TSS_SUCCESS;
	TSS_HKEY hEK;
	TSS_HPOLICY hTPMPolicy;
	BYTE bSecret[32] = {0};
	UINT32 uiSecret = 0;

	if(hTPM == NULL){
		std::cout << "hTPM pointer cannot be NULL." << std::endl;
		return;
	}

	res = Tspi_TPM_GetPubEndorsementKey(*hTPM, FALSE, NULL, &hEK);
	if (res != TSS_SUCCESS) {
		std::cout << "Tspi_TPM_GetPubEndorsementKey failed." << std::endl;
		std::cout << Trspi_Error_String(res) << std::endl;
		if(ERROR_CODE(res) == TPM_E_DISABLED_CMD) {
			std::cout << "Enter owner password: ";
			std::cin >> bSecret;
			uiSecret = strlen((char*)bSecret);
			if(uiSecret <= 0) {
				std::cout << "Owner password cannot be NULL." << std::endl;
				return;
			}
			
			if(!bSecret) {
				std::cout << "Incorrect owner password." << std::endl;
				return;
			}
			Tspi_GetPolicyObject(*hTPM, TSS_POLICY_USAGE, &hTPMPolicy );
			Tspi_Policy_SetSecret( hTPMPolicy, TSS_SECRET_MODE_PLAIN,
					   uiSecret, bSecret);
			res = Tspi_TPM_GetPubEndorsementKey(*hTPM, TRUE, NULL, &hEK);
			if(res != TSS_SUCCESS){
				std::cout << "Failed to get public endorsement key." << std::endl;
				std::cout << Trspi_Error_String(res) << std::endl;
				return;
			}
			displayKey(hEK);
		}
	}//if	
	return;
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

	//Create Context
	res = connect_load_all(&hContext, &hSRK, &hTPM);
	if (res != TSS_SUCCESS) {
		print_error("connect_load_all", res);
		exit(res);
	}	
                           
    //Get public endorsement key
	//GetPubEK(&hTPM);

	CreateAIK(&hContext, &hTPM, &hSRK);
	
END:
	Tspi_Context_FreeMemory(hContext, NULL);
	Tspi_Context_Close(hContext);
	
	return 0;
}
