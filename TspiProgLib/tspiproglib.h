#ifndef TSPIPROGLIB_LIBRARY_H
#define TSPIPROGLIB_LIBRARY_H

#include "tpm_general_inc.h"

void	hex_print(char* data, int length);
void	char_print(char* data, int length);
int 	MyFunc_Init(TSS_HCONTEXT *context, TSS_HTPM *tpm, BYTE *secret);
int		MyFunc_CreateTPMKey(TSS_HCONTEXT *context, TSS_HKEY *srk, TSS_HKEY *tpm_key);
int		MyFunc_CreateTPMKey2(TSS_HCONTEXT *context, TSS_HKEY *srk, TSS_HKEY *tpm_key, TSS_FLAG key_flags);
int		MyFunc_DataBinding(TSS_HCONTEXT *context, UINT32 in_size, BYTE *in,
                              UINT32 *out_size, BYTE *out, TSS_HKEY *tpm_key);
int     MyFunc_DataUnbinding(TSS_HCONTEXT *context, TSS_HKEY *tpm_key,
                             UINT32 in_size, BYTE* in,
                             UINT32 *unbind_data_size, BYTE** unbind_data);
int     MyFunc_DataSeal(TSS_HCONTEXT *context, TSS_HTPM *tpm, TSS_HKEY *key, 
						UINT32 in_size, BYTE *in,
                        UINT32 *out_size, BYTE **out,
                        TSS_HPCRS *pcrs);
int     MyFunc_DataUnseal(TSS_HCONTEXT *context, TSS_HKEY *tpm_key, 
						UINT32 in_size, BYTE *in,
						UINT32 *unsealed_data_size, BYTE **unsealed_data);
int     MyFunc_ReadPCR(TSS_HCONTEXT *context, TSS_HTPM *tpm, UINT32 pcr_index, 
						UINT32 *out_size, BYTE **out);
int     MyFunc_PrintAllPCRs(TSS_HCONTEXT *context, TSS_HTPM *tpm);
int     MyFunc_ExtendPCR(TSS_HCONTEXT *context, TSS_HTPM *tpm, UINT32 pcr_index,
                            UINT32 in_size, BYTE* in,
                            UINT32 *out_size, BYTE** out);
int		MyFunc_CreatePCRs(TSS_HCONTEXT *context, 
							TSS_HTPM *tpm,
							UINT32 num_PCRs, UINT32 *PCRs, TSS_HPCRS *hPCRs);
#endif
