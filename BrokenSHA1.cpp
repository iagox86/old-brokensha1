#include "BrokenSHA1.h"

void BrokenSHA1::hashData(const char *data, int length, DWORD returnBuffer[5])
{
	char currentHashData[0x40];

	getInitialData(returnBuffer);

	// we do it in blocks of 0x40 bytes
	while(length > 0)
	{
		int bytesToCopy = 0x40;
		// If it's less bytes, then we copy less bytes
		if(length < bytesToCopy)
		{
			// Copy less if we have less
			bytesToCopy = length;
		}

		// Copy the data over
		memcpy(currentHashData, data, bytesToCopy);

		// Subtract what we've done from the length
		length -= bytesToCopy;

		// Increment the data
		data += bytesToCopy;

		// Fill the rest of the buffer with 0
		for(int i = bytesToCopy; i < 0x40; i++)
		{
			currentHashData[i] = 0;
		}

		// Now all that's left is to hash this part and go onto the next
		hashNextPart(currentHashData, returnBuffer);
	}

}

void BrokenSHA1::getInitialData(DWORD returnBuffer[5])
{
//	mov     dword ptr [ecx], 67452301h
	returnBuffer[0] =      0x67452301ul;
//	mov     dword ptr [ecx+4], 0EFCDAB89h
	returnBuffer[1] =        0x0EFCDAB89ul;
//	mov     dword ptr [ecx+8], 98BADCFEh
	returnBuffer[2] =        0x98BADCFEul;
//	mov     dword ptr [ecx+0Ch], 10325476h
	returnBuffer[3] =          0x10325467ul;
//	mov     dword ptr [ecx+10h], 0C3D2E1F0h
	returnBuffer[4] =          0xC3D2E1F0ul;
}

void BrokenSHA1::hashNextPart(char Data[0x40], DWORD hashBuffer[5])
{
	// Declare lots of local variables
	DWORD a = 0, 
		b = 0, 
		c = 0, 
		d = 0, 
		e = 0, 
		f = 0, 
		g = 0, 
		h = 0, 
		i = 0, 
		j = 0;

	unsigned char copyHashData[0x140];
//		mov     ebp, ecx                ; ebp = ReturnBuffer
//		mov     ecx, 10h                ; we're moving 0x10 dword's, or 0x40 bytes
//		lea     esi, [ebp+14h]          ; starting at the 0x14th character of the hashBuffer
//		lea     edi, [esp+15Ch+copyHashData] ; into copyHashData
//		rep movsd
	memset(copyHashData, 0, sizeof(copyHashData));
	memcpy(copyHashData, Data, 0x40);
//		mov     [esp+15Ch+ptrReturnBuffer], ebp
//		lea     edx, [esp+15Ch+copyHashData+8] ; edx = 8th character of copyHashData
	unsigned char *shuffleLocation = copyHashData + 8;
//		mov     esi, 40h                ; 
//										; 
//										; Do the following chunk 0x40 times:
	for(int i = 0; i < 0x40; i++)
	{
//		mov     eax, [edx+2Ch]          ; eax = chunk of memory
		a = shuffleLocation[0x2C];

//		mov     ebx, [edx+18h]          ; ebx = chunk of memory
		b = shuffleLocation[0x18];

//		mov     edi, [edx-8]            ; edi = chunk of memory
		c = shuffleLocation[-0x08];

//		mov     ecx, [edx]              ; ecx = chunk of memory
		d = shuffleLocation[0x00];

//		xor     eax, ebx                ; eax = eax ^ ebx
		a = a ^ b;

//		mov     ebx, 1                  ; ebx = 1
		b = 1;
//		xor     eax, edi                ; eax = eax & edi
		a = a & c;

//		mov     edi, 1                  ; edi = 1
		c = 1;

//		xor     eax, ecx                ; eax = eax ^ ecx
		a = a ^ d;

//		mov     ecx, 20h                ; ecx = 0x20
		d = 0x20;

//		and     eax, 1Fh                ; eax = eax & 0x1F
		a = a & 0x1F;

//		add     edx, 4                  ; edx += 4
		shuffleLocation += 4;

//		sub     ecx, eax                ; ecx = ecx - eax
		d = d - a;

//		sar     edi, cl                 ; edi = edi >> ecx
		c = c >> d;

//		mov     ecx, eax                ; ecx = eax
		d = a;

//		shl     ebx, cl                 ; ebx = ebx << ecx
		b = b << d;

//		or      edi, ebx                ; edi = edi | ebx
		c = c | b;

//		dec     esi                     ; esi--
//		mov     [edx+34h], edi
		*((DWORD*)(shuffleLocation + 0x34)) = c;
//		jnz     short FirstLoop         ; } while esi != 0
	}
//		//		//		//		; 
//		//		//		//		; (After this I'm going to name variables a, b, c, etc.
//		mov     ebx, [ebp+0]            ; a = ReturnBuffer[0]
//		mov     eax, [ebp+4]            ; b = ReturnBuffer[1]
//		mov     edx, [ebp+8]            ; c = ReturnBuffer[2]
//		mov     esi, [ebp+0Ch]          ; d = ReturnBuffer[3]
//		mov     ebp, [ebp+10h]          ; e = ReturnBuffer[4]
//		mov     [esp+15Ch+h], ebx       ; h = a
//		mov     [esp+15Ch+i], ebp       ; i = e
//		xor     edi, edi                ; inc = 0

//		SecondLoop:                             ; CODE XREF: Hash40Bytes+BFj
//		mov     ecx, eax                ; f = b
//		mov     ebp, edx                ; g = c
//		not     ecx                     ; f = ~f
//		and     ecx, esi                ; f = f & d
//		and     ebp, eax                ; g = g & b
//		or      ecx, ebp                ; f = f | g
//		mov     ebp, ebx                ; g = a
//		shr     ebp, 1Bh                ; a = a >> 0x18
//		shl     ebx, 5                  ; a = a << 0x05
//		or      ebp, ebx                ; g = g | a
//		mov     ebx, [esp+15Ch+i]       ; ebx = i
//		add     ecx, ebp                ; f = f + g
//		mov     ebp, dword ptr [esp+edi*4+15Ch+ptrHashData] ; g = HashData[inc]
//		add     ecx, ebp                ; f = f + g
//		mov     ebp, esi                ; f = d
//		mov     esi, edx                ; d = c
//		mov     edx, eax                ; c = b
//		shl     edx, 1Eh                ; c = c << 0x1E
//		shr     eax, 2                  ; b = b >> 2
//		lea     ecx, [ecx+ebx+5A827999h] ; f = f + i + 0x5A827999
//		or      edx, eax                ; c = c | b
//		mov     eax, [esp+15Ch+h]       ; eax = a
//		inc     edi                     ; Add 1 to the incrementer
//		mov     ebx, ecx                ; i = f
//		cmp     edi, 14h                ; Compare the incrementer to 0x14 (20)
//		mov     [esp+15Ch+i], ebp
//		mov     [esp+15Ch+h], ebx
//		jb      short SecondLoop        ; loop while (inc < 0x14)
//		cmp     edi, 28h                ; if edi > 0x28
//		jnb     short loc_190125D9      ; jump down

//		ThirdLoop:                              ; CODE XREF: Hash40Bytes+103j
//		mov     ebp, ecx
//		shr     ebp, 1Bh
//		shl     ecx, 5
//		or      ebp, ecx
//		mov     ecx, esi
//		xor     ecx, edx
//		xor     ecx, eax
//		add     ebp, ecx
//		mov     ecx, dword ptr [esp+edi*4+15Ch+ptrHashData]
//		add     ebp, ecx
//		mov     ecx, [esp+15Ch+i]
//		lea     ecx, [ecx+ebp+6ED9EBA1h]
//		mov     ebp, esi
//		mov     esi, edx
//		mov     edx, eax
//		shl     edx, 1Eh
//		shr     eax, 2
//		or      edx, eax
//		inc     edi
//		mov     eax, ebx
//		cmp     edi, 28h
//		mov     [esp+15Ch+i], ebp
//		mov     ebx, ecx
//		jb      short ThirdLoop
//		mov     [esp+15Ch+h], ebx

//		loc_190125D9:                           ; CODE XREF: Hash40Bytes+C4j
//		cmp     edi, 3Ch
//		jnb     short loc_19012629

//		FourthLoop:                             ; CODE XREF: Hash40Bytes+157j
//		mov     ebx, edx
//		mov     ebp, edx
//		or      ebx, eax
//		and     ebp, eax
//		and     ebx, esi
//		or      ebx, ebp
//		mov     ebp, ecx
//		shr     ebp, 1Bh
//		shl     ecx, 5
//		or      ebp, ecx
//		mov     ecx, [esp+15Ch+i]
//		add     ebx, ebp
//		mov     ebp, dword ptr [esp+edi*4+15Ch+ptrHashData]
//		add     ebx, ebp
//		mov     ebp, esi
//		mov     esi, edx
//		mov     edx, eax
//		shl     edx, 1Eh
//		shr     eax, 2
//		lea     ecx, [ebx+ecx-70E44324h]
//		or      edx, eax
//		mov     eax, [esp+15Ch+h]
//		inc     edi
//		mov     ebx, ecx
//		cmp     edi, 3Ch
//		mov     [esp+15Ch+i], ebp
//		mov     [esp+15Ch+h], ebx
//		jb      short FourthLoop

//		loc_19012629:                           ; CODE XREF: Hash40Bytes+10Cj
//		cmp     edi, 50h
//		jnb     short SixthLoop

//		FifthLoop:                              ; CODE XREF: Hash40Bytes+19Bj
//		mov     ebp, ecx
//		shr     ebp, 1Bh
//		shl     ecx, 5
//		or      ebp, ecx
//		mov     ecx, esi
//		xor     ecx, edx
//		xor     ecx, eax
//		add     ebp, ecx
//		mov     ecx, dword ptr [esp+edi*4+15Ch+ptrHashData]
//		add     ebp, ecx
//		mov     ecx, [esp+15Ch+i]
//		lea     ecx, [ecx+ebp-359D3E2Ah]
//		mov     ebp, esi
//		mov     esi, edx
//		mov     edx, eax
//		shl     edx, 1Eh
//		shr     eax, 2
//		or      edx, eax
//		inc     edi
//		mov     eax, ebx
//		cmp     edi, 50h
//		mov     [esp+15Ch+i], ebp
//		mov     ebx, ecx
//		jb      short FifthLoop

//		SixthLoop:                              ; CODE XREF: Hash40Bytes+15Cj
//		mov     edi, [esp+15Ch+ptrReturnBuffer]
//		mov     ebx, [edi]
//		add     ebx, ecx
//		mov     ecx, [edi+4]
//		add     ecx, eax
//		mov     eax, [edi+8]
//		add     eax, edx
//		mov     [edi], ebx
//		mov     [edi+8], eax
//		mov     eax, [edi+0Ch]
//		add     eax, esi
//		mov     [edi+4], ecx
//		mov     [edi+0Ch], eax
//		mov     eax, [edi+10h]
//		add     eax, ebp
//		mov     [edi+10h], eax



}