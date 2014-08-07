/*****************************************************************************/
/* SFileSign.cpp                          Copyright (c) Ladislav Zezula 2010 */
/*---------------------------------------------------------------------------*/
/* MPQ files and MPQ archives verification.                                  */
/*                                                                           */
/* The MPQ signature verification has been written by Jean-Francois Roy      */
/* <bahamut@macstorm.org> and Justin Olbrantz (Quantam).                     */
/* The MPQ public keys have been created by MPQKit, using OpenSSL library.   */
/*                                                                           */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 04.05.10  1.00  Lad  The first version of SFileVerify.cpp                 */
/*****************************************************************************/

#define __STORMLIB_SELF__
#include "StormLib.h"
#include "StormCommon.h"

//-----------------------------------------------------------------------------
// Local defines

#define MPQ_DIGEST_UNIT_SIZE      0x10000

//-----------------------------------------------------------------------------
// Cracked Blizzard private keys
// Created by Tianyi HE using cado-nfs

static const char * szBlizzardWeakPrivateKey =
    "-----BEGIN PRIVATE KEY-----"
    "MIIBOQIBAAJBAJJidwS/uILMBSO5DLGsBFknIXWWjQJe2kfdfEk3G/j66w4KkhZ1"
    "V61Rt4zLaMVCYpDun7FLwRjkMDSepO1q2DcCAwEAAQJANtiztVDMJh2hE1hjPDKy"
    "UmEJ9U/aN3gomuKOjbQbQ/bWWcM/WfhSVHmPqtqh/bQI2UXFr0rnXngeteZHLr/b"
    "8QIhAMuWriSKGMACw18/rVVfUrThs915odKBH1Alr3vMVVzZAiEAuBHPSQkgwcb6"
    "L4MWaiKuOzq08mSyNqPeN8oSy18q848CIHeMn+3s+eOmu7su1UYQl6yH7OrdBd1q"
    "3UxfFNEJiAbhAiAqxdCyOxHGlbM7aS3DOg3cq5ayoN2cvtV7h1R4t8OmVwIgF+5z"
    "/6vkzBUsZhd8Nwyis+MeQYH0rpFpMKdTlqmPF2Q="
    "-----END PRIVATE KEY-----";

//-----------------------------------------------------------------------------
// Local functions

static void memrev(unsigned char *buf, size_t count)
{
    unsigned char *r;

    for (r = buf + count - 1; buf < r; buf++, r--)
    {
        *buf ^= *r;
        *r   ^= *buf;
        *buf ^= *r;
    }
}

static bool decode_base64_key(const char * szKeyBase64, rsa_key * key)
{
    unsigned char decoded_key[0x200];
    const char * szBase64Begin;
    const char * szBase64End;
    unsigned long decoded_length = sizeof(decoded_key);
    unsigned long length;

    // Find out the begin of the BASE64 data
    szBase64Begin = szKeyBase64 + strlen("-----BEGIN PUBLIC KEY-----");
    szBase64End   = szBase64Begin + strlen(szBase64Begin) - strlen("-----END PUBLIC KEY-----");
    if(szBase64End[0] != '-')
        return false;

    // decode the base64 string
    length = (unsigned long)(szBase64End - szBase64Begin);
    if(base64_decode((unsigned char *)szBase64Begin, length, decoded_key, &decoded_length) != CRYPT_OK)
        return false;

    // Create RSA key
    if(rsa_import(decoded_key, decoded_length, key) != CRYPT_OK)
        return false;

    return true;
}

static bool CalculateMpqHashMd5(
    TMPQArchive * ha,
    PMPQ_SIGNATURE_INFO pSI,
    LPBYTE pMd5Digest)
{
    hash_state md5_state;
    ULONGLONG BeginBuffer;
    ULONGLONG EndBuffer;
    LPBYTE pbDigestBuffer = NULL;

    // Allocate buffer for creating the MPQ digest.
    pbDigestBuffer = STORM_ALLOC(BYTE, MPQ_DIGEST_UNIT_SIZE);
    if(pbDigestBuffer == NULL)
        return false;

    // Initialize the MD5 hash state
    md5_init(&md5_state);

    // Set the byte offset of begin of the data
    BeginBuffer = pSI->BeginMpqData;

    // Create the digest
    for(;;)
    {
        ULONGLONG BytesRemaining;
        LPBYTE pbSigBegin = NULL;
        LPBYTE pbSigEnd = NULL;
        DWORD dwToRead = MPQ_DIGEST_UNIT_SIZE;

        // Check the number of bytes remaining
        BytesRemaining = pSI->EndMpqData - BeginBuffer;
        if(BytesRemaining < MPQ_DIGEST_UNIT_SIZE)
            dwToRead = (DWORD)BytesRemaining;
        if(dwToRead == 0)
            break;

        // Read the next chunk 
        if(!FileStream_Read(ha->pStream, &BeginBuffer, pbDigestBuffer, dwToRead))
        {
            STORM_FREE(pbDigestBuffer);
            return false;
        }

        // Move the current byte offset
        EndBuffer = BeginBuffer + dwToRead;

        // Check if the signature is within the loaded digest
        if(BeginBuffer <= pSI->BeginExclude && pSI->BeginExclude < EndBuffer)
            pbSigBegin = pbDigestBuffer + (size_t)(pSI->BeginExclude - BeginBuffer);
        if(BeginBuffer <= pSI->EndExclude && pSI->EndExclude < EndBuffer)
            pbSigEnd = pbDigestBuffer + (size_t)(pSI->EndExclude - BeginBuffer);

        // Zero the part that belongs to the signature
        if(pbSigBegin != NULL || pbSigEnd != NULL)
        {
            if(pbSigBegin == NULL)
                pbSigBegin = pbDigestBuffer;
            if(pbSigEnd == NULL)
                pbSigEnd = pbDigestBuffer + dwToRead;

            memset(pbSigBegin, 0, (pbSigEnd - pbSigBegin));
        }

        // Pass the buffer to the hashing function
        md5_process(&md5_state, pbDigestBuffer, dwToRead);

        // Move pointers
        BeginBuffer += dwToRead;
    }

    // Finalize the MD5 hash
    md5_done(&md5_state, pMd5Digest);
    STORM_FREE(pbDigestBuffer);
    return true;
}

static DWORD CreateWeakSignature(
    TMPQArchive * ha,
    PMPQ_SIGNATURE_INFO pSI,
    BYTE * signature,
    unsigned long * signature_len)
{
    BYTE Md5Digest[MD5_DIGEST_SIZE];
    rsa_key key;
    int hash_idx = find_hash("md5");

    if(!CalculateMpqHashMd5(ha, pSI, Md5Digest))
        return ERROR_VERIFY_FAILED;

    if(!decode_base64_key(szBlizzardWeakPrivateKey, &key))
        return ERROR_VERIFY_FAILED;

    rsa_sign_hash_ex(Md5Digest, sizeof(Md5Digest), signature, signature_len, LTC_LTC_PKCS_1_V1_5, 0, 0, hash_idx, 0, &key);
    rsa_free(&key);
	memrev(signature, MPQ_WEAK_SIGNATURE_SIZE);
    return 0;
}

//-----------------------------------------------------------------------------
// Public (exported) functions

DWORD WINAPI SFileAllocateWeakSignature(HANDLE hMpq)
{
    char buf[MPQ_WEAK_SIGNATURE_SIZE + 8];
	unsigned long len;
    HANDLE f;
    MPQ_SIGNATURE_INFO si;
    TMPQArchive * ha = (TMPQArchive *)hMpq;

    // Verify input parameters
    if(!IsValidMpqHandle(hMpq))
        return ERROR_INVALID_PARAMETER;

    // Get the MPQ signature and signature type
    memset(&si, 0, sizeof(MPQ_SIGNATURE_INFO));
    if(!QueryMpqSignatureInfo(ha, &si))
        return ERROR_QUERY_FAILED;

	if (si.SignatureTypes & SIGNATURE_TYPE_STRONG) {
		// already has a strong signature, cannot sign again
		return ERROR_ALREADY_SIGNED;
	} else if (si.SignatureTypes == SIGNATURE_TYPE_NONE) {
		SFileCreateFile(ha, "(signature)", 0, MPQ_WEAK_SIGNATURE_SIZE + 8, 0, 0, &f);
		SFileWriteFile(f, buf, MPQ_WEAK_SIGNATURE_SIZE + 8, 0);
		SFileFinishFile(f);
	}

    return ERROR_SUCCESS;
}

DWORD WINAPI SFileSignArchiveWeak(HANDLE hMpq)
{
    char buf[MPQ_WEAK_SIGNATURE_SIZE + 8];
	unsigned long len;
    HANDLE f;
    MPQ_SIGNATURE_INFO si;
    TMPQArchive * ha = (TMPQArchive *)hMpq;

    // Verify input parameters
    if(!IsValidMpqHandle(hMpq))
        return ERROR_INVALID_PARAMETER;

    // Get the MPQ signature and signature type
    memset(&si, 0, sizeof(MPQ_SIGNATURE_INFO));
    if(!QueryMpqSignatureInfo(ha, &si))
        return ERROR_QUERY_FAILED;

    assert(si.SignatureTypes == SIGNATURE_TYPE_WEAK);

	// calculate signature
	memset(buf, 0, 8);
	CreateWeakSignature(ha, &si, (BYTE *)(buf+8), &len);

	// overwrite signature sector
	ULONGLONG offset = si.BeginExclude;
	FileStream_Write(ha->pStream, &offset, buf, MPQ_WEAK_SIGNATURE_SIZE + 8);

    return ERROR_SUCCESS;
}
