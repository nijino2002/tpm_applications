#ifndef TSPIPROGLIB_LIBRARY_H
#define TSPIPROGLIB_LIBRARY_H

#include "tpm_general_inc.h"

void	hex_print(char* data, int length);
int		MyFunc_CreateTPMKey(TSS_HCONTEXT *context, TSS_HKEY *srk, TSS_HKEY *tpm_key);
int		MyFunc_DataBinding(TSS_HCONTEXT *context, UINT32 in_size, BYTE *in,
                              UINT32 *out_size, BYTE *out, TSS_HKEY *tpm_key);
int     MyFunc_DataUnbinding(TSS_HCONTEXT *context, TSS_HKEY *tpm_key,
                             UINT32 in_size, BYTE* in,
                             UINT32 *unbind_data_size, BYTE** unbind_data);
int     MyFunc_DataSeal();
int     MyFunc_DataUnseal();
int     MyFunc_ReadPCR();
int     MyFunc_PrintAllPCRs(TSS_HCONTEXT *context, TSS_HTPM *tpm);
int     MyFunc_ExtendPCR(TSS_HCONTEXT *context, TSS_HTPM *tpm, UINT32 pcr_index,
                            UINT32 in_size, BYTE* in,
                            UINT32 *out_size, BYTE** out);

#endif