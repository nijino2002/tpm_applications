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

#define CA_KEY_SIZE_BITS 2048
#define MY_UUID_AIK {0,0,0,0,0,{'M','Y','_','A','I','K'}}

void GetPubEK(TSS_HTPM *hTPM);
TSS_RESULT CreateAIK(TSS_HCONTEXT *hContext, TSS_HTPM *hTPM, TSS_HKEY *hSRK, TSS_HKEY *hAIK);
TSS_RESULT GetPubKey(TSS_HKEY *key, TSS_HKEY *hSRK, UINT32 *keylen, BYTE **bKey);

TSS_RESULT CreateAIK(TSS_HCONTEXT *hContext, TSS_HTPM *hTPM, TSS_HKEY *hSRK, TSS_HKEY *hAIK) {
	TSS_RESULT res = TSS_SUCCESS;
	TSS_HKEY hWrappingKey, hSigningKey, hCAKey;
	TSS_HPOLICY hTPMPolicy;
	RSA		*rsa = NULL;
	unsigned char	n[2048];//, p[2048];
	int		size_n;//, size_p;
	BYTE		*rgbIdentityLabelData = NULL, *rgbTCPAIdentityReq;
	BYTE		*labelString = "My Identity Label";
	UINT32		labelLen = strlen(labelString) + 1;
	UINT32		ulTCPAIdentityReqLength;

	char *nameOfFunction = "CreateAIK";

	UINT32 initFlags	= TSS_KEY_TYPE_IDENTITY | TSS_KEY_SIZE_2048  |
			TSS_KEY_VOLATILE | TSS_KEY_NO_AUTHORIZATION |
			TSS_KEY_NOT_MIGRATABLE;

	res = Testsuite_Transport_Init(*hContext, *hSRK, *hTPM, TRUE, FALSE, &hWrappingKey, &hSigningKey);
	if(res != TSS_SUCCESS){
		print_error("Testsuite_Transport_Init failed.", res);
		return res;
	}

	//Insert the owner auth into the TPM's policy
	res = Tspi_GetPolicyObject(*hTPM, TSS_POLICY_USAGE, &hTPMPolicy);
	if (res != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", res);
		return res;
	}

	res = Tspi_Policy_SetSecret(hTPMPolicy, TESTSUITE_OWNER_SECRET_MODE,
				       TESTSUITE_OWNER_SECRET_LEN, TESTSUITE_OWNER_SECRET);
	if (res != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", res);
		return res;
	}

	//Create Identity Key Object
	res = Tspi_Context_CreateObject(*hContext,
					   TSS_OBJECT_TYPE_RSAKEY,
					   initFlags, hAIK);
	if (res != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", res);
		Tspi_Context_Close(*hContext);
		return res;
	}

	//Create CA Key Object
	res = Tspi_Context_CreateObject(*hContext,
					   TSS_OBJECT_TYPE_RSAKEY,
					   TSS_KEY_TYPE_LEGACY|TSS_KEY_SIZE_2048,
					   &hCAKey);
	if (res != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", res);
		Tspi_Context_Close(*hContext);
		return res;
	}

		// generate a software key to represent the CA's key
	if ((rsa = RSA_generate_key(CA_KEY_SIZE_BITS, 65537, NULL, NULL)) == NULL) {
		print_error("RSA_generate_key", 1);
		Tspi_Context_Close(*hContext);
		return res;
	}

		// get the pub CA key
	if ((size_n = BN_bn2bin(rsa->n, n)) <= 0) {
		fprintf(stderr, "BN_bn2bin failed\n");
		Tspi_Context_Close(*hContext);
		RSA_free(rsa);
                exit(254);
        }

		// set the CA's public key data in the TSS object
	res = set_public_modulus(*hContext, hCAKey, size_n, n);
	if (res != TSS_SUCCESS) {
		print_error("set_public_modulus", res);
		Tspi_Context_Close(*hContext);
		RSA_free(rsa);
		return res;
	}

		// set the CA key's algorithm
	res = Tspi_SetAttribUint32(hCAKey, TSS_TSPATTRIB_KEY_INFO,
				      TSS_TSPATTRIB_KEYINFO_ALGORITHM,
				      TSS_ALG_RSA);
	if (res != TSS_SUCCESS) {
		print_error("Tspi_SetAttribUint32", res);
		Tspi_Context_Close(*hContext);
		RSA_free(rsa);
		return res;
	}

		// set the CA key's number of primes
	res = Tspi_SetAttribUint32(hCAKey, TSS_TSPATTRIB_RSAKEY_INFO,
				      TSS_TSPATTRIB_KEYINFO_RSA_PRIMES,
				      2);
	if (res != TSS_SUCCESS) {
		print_error("Tspi_SetAttribUint32", res);
		Tspi_Context_Close(*hContext);
		RSA_free(rsa);
		return res;
	}

	rgbIdentityLabelData = TestSuite_Native_To_UNICODE(labelString, &labelLen);
	if (rgbIdentityLabelData == NULL) {
		fprintf(stderr, "TestSuite_Native_To_UNICODE failed\n");
		Tspi_Context_Close(*hContext);
		RSA_free(rsa);
                return res;
	}

	//Create AIK
	res = Tspi_TPM_CollateIdentityRequest(*hTPM, *hSRK, hCAKey, labelLen,
						 rgbIdentityLabelData,
						 *hAIK, TSS_ALG_AES,
						 &ulTCPAIdentityReqLength,
						 &rgbTCPAIdentityReq);
	if (res != TSS_SUCCESS) {
		print_error("Tspi_TPM_CollateIdentityRequest", res);
		Tspi_Context_Close(*hContext);
		RSA_free(rsa);
		return res;
	}

	res = Testsuite_Transport_Final(*hContext, hSigningKey);
	if (res != TSS_SUCCESS){
		if(!checkNonAPI(res)){
			print_error(nameOfFunction, res);
			print_end_test(nameOfFunction);
			Tspi_Context_Close(*hContext);
			RSA_free(rsa);
			return res;
		}
		else{
			print_error_nonapi(nameOfFunction, res);
			print_end_test(nameOfFunction);
			Tspi_Context_Close(*hContext);
			RSA_free(rsa);
			return res;
		}
	}
	else{
		res = Tspi_Context_FreeMemory(*hContext, rgbTCPAIdentityReq);
		if (res != TSS_SUCCESS) {
			print_error("Tspi_Context_FreeMemory ", res);
			Tspi_Context_Close(*hContext);
			return res;
		}
		print_success(nameOfFunction, res);
		print_end_test(nameOfFunction);
		RSA_free(rsa);
	}

	return res;
}

TSS_RESULT GetPubKey(TSS_HKEY *key, TSS_HKEY *hSRK, UINT32 *keylen, BYTE **bKey){
	TSS_RESULT res = TSS_SUCCESS;

	res = Tspi_Key_LoadKey( *key, *hSRK );
	if(res != TSS_SUCCESS){
		print_error("Loading key failed.",res);
		return res;
	}

	res = Tspi_Key_GetPubKey(*key, keylen, bKey);
	if(res != TSS_SUCCESS){
		print_error("Getting PubKey failed.",res);
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

TSS_RESULT RegisterKey(TSS_HCONTEXT *hContext, TSS_HKEY *hSRK, TSS_HKEY *hKey, TSS_UUID keyuuid){
	TSS_RESULT res = TSS_SUCCESS;
	TSS_UUID SRK_UUID = TSS_UUID_SRK;
	
	if(hContext == NULL || hSRK == NULL || hKey == NULL){
		print_error("RegisterKey: null parameters found.", res);
		return TSS_E_BAD_PARAMETER;
	}

	res = Tspi_Context_RegisterKey(*hContext, *hKey, TSS_PS_TYPE_USER, keyuuid, TSS_PS_TYPE_SYSTEM, SRK_UUID);
	if(res != TSS_SUCCESS){
		print_error("RegisterKey: executing Tspi_Context_RegisterKey failed.",res);
		return res;
	}

	return res;
}

TSS_RESULT SavePubKeyToFile(){
	TSS_RESULT res = TSS_SUCCESS;

	return res;
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
	TSS_HPOLICY		hAIKPolicy, hLoadedAIKPolicy;
	TSS_HKEY loadedAIK;
	BYTE *AIKPub = NULL;
	UINT32 AIKPubLen = 0;
	UINT32 EK_CERT_NV_INDEX = TPM_NV_INDEX_EKCert;
	UINT32 ulPubAIKeyLength;
	BYTE *rgbPubAIKey = NULL;
	TSS_UUID AIK_UUID = MY_UUID_AIK;
	UINT32 AIKInitFlags	= TSS_KEY_TYPE_IDENTITY | TSS_KEY_SIZE_2048  |
			TSS_KEY_VOLATILE | TSS_KEY_NO_AUTHORIZATION |
			TSS_KEY_NOT_MIGRATABLE;

	//Create Context
	res = connect_load_all(&hContext, &hSRK, &hTPM);
	if (res != TSS_SUCCESS) {
		print_error("connect_load_all", res);
		exit(res);
	}	
                           
    //Get public endorsement key
	//GetPubEK(&hTPM);

	res = CreateAIK(&hContext, &hTPM, &hSRK, &hAIKey);
	if(res != TSS_SUCCESS){
		print_error("Creating AIK failed.",res);
		goto END;
	}

	res = GetPubKey(&hAIKey, &hSRK, &ulPubAIKeyLength, &rgbPubAIKey);
	if(res != TSS_SUCCESS) {
		print_error("GetPubKey failed.", res);
		goto END;
	}
	//print_hex(rgbPubAIKey, ulPubAIKeyLength);
	displayKey(hAIKey);
	Tspi_Context_FreeMemory(hContext, rgbPubAIKey);
	rgbPubAIKey = NULL;

	//Register AIK to persistent storage
	//res = RegisterKey(&hContext, &hSRK, &hAIKey,AIK_UUID); 

	//Create Identity Key Object
	res = Tspi_Context_CreateObject(hContext,
					   TSS_OBJECT_TYPE_RSAKEY,
					   AIKInitFlags, &loadedAIK);
	if(res != TSS_SUCCESS) {
		print_error("CreateObject loadedAIK failed.", res);
	}

	res = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_USER, AIK_UUID, &loadedAIK);
	if(res != TSS_SUCCESS){
		print_error("LoadKeyByUUID: failed.",res);
	}

	//res = GetPubKey(&loadedAIK, &hSRK, &ulPubAIKeyLength, &rgbPubAIKey);
	//std::cout<< "Display Loaded PubAIK" << std::endl;
	//displayKey(loadedAIK);
	//Tspi_Context_FreeMemory(hContext, rgbPubAIKey);

END:
	Tspi_Context_FreeMemory(hContext, NULL);
	Tspi_Context_Close(hContext);
	
	return 0;
}
