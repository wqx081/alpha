/* ============================================================================
 * Copyright (c) 2010-2015.  All rights reserved.
 * SM3 Hash Cipher Algorithm: Digest length is 256-bit
 * ============================================================================
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "sm3.h"


#define nl2c(l,c)	(*((c)++) = (unsigned char)(((l) >> 24) & 0xff), \
					 *((c)++) = (unsigned char)(((l) >> 16) & 0xff), \
					 *((c)++) = (unsigned char)(((l) >> 8)  & 0xff), \
					 *((c)++) = (unsigned char)(((l)    )   & 0xff))

#define c_2_nl(c)	((*(c) << 24) | (*(c+1) << 16) | (*(c+2) << 8) | *(c+3))
#define ROTATE(X, C) (((X) << (C)) | ((X) >> (32 - (C))))

#define TH 0x79cc4519
#define TL 0x7a879d8a
#define FFH(X, Y, Z) ((X) ^ (Y) ^ (Z))
#define FFL(X, Y, Z) (((X) & (Y)) | ((X) & (Z)) | ((Y) & (Z)))
#define GGH(X, Y, Z) ((X) ^ (Y) ^ (Z))
#define GGL(X, Y, Z) (((X) & (Y)) | ((~X) & (Z)))
#define P0(X)  ((X) ^ (((X) << 9) | ((X) >> 23)) ^ (((X) << 17) | ((X) >> 15)))
#define P1(X)  ((X) ^ (((X) << 15) | ((X) >> 17)) ^ (((X) << 23) | ((X) >> 9)))

#define DEBUG_SM3 0

#if DEBUG_SM3
void PrintBuf(unsigned char *buf, int	buflen) 
{
	int i;
	printf("\n");
	printf("len = %d\n", buflen);
	for(i=0; i<buflen; i++) {
  	if (i % 32 != 31)
  	  printf("%02x", buf[i]);
  	  else
  	  printf("%02x\n", buf[i]);
  }
  printf("\n");
  return;
}
#endif

void sm3_block(SM3_CTX *ctx)
{
	register int j, k;
	register unsigned int t;
	register unsigned int ss1, ss2, tt1, tt2;
	register unsigned int a, b, c, d, e, f, g, h;
	unsigned int w[132];


	for(j = 0; j < 16; j++)
		w[j] = ctx->data[j];

	for(j = 16; j < 68; j++)
	{
		t = w[j-16] ^ w[j-9] ^ ROTATE(w[j-3], 15);
		w[j] = P1(t) ^ ROTATE(w[j-13], 7) ^ w[j-6];
	}


	for(j = 0, k = 68; j < 64; j++, k++)
	{
		w[k] = w[j] ^ w[j+4];
	}


	a = ctx->h[0];
	b = ctx->h[1];
	c = ctx->h[2];
	d = ctx->h[3];
	e = ctx->h[4];
	f = ctx->h[5];
	g = ctx->h[6];
	h = ctx->h[7];

	for(j = 0; j < 16; j++)
	{
		ss1 = ROTATE(ROTATE(a, 12) +  e + ROTATE(TH, j), 7);
		ss2 = ss1 ^ ROTATE(a, 12);
		tt1 = FFH(a, b, c) + d + ss2 + w[68 + j];
		tt2 = GGH(e, f, g) + h + ss1 + w[j];

		d = c; 
		c = ROTATE(b, 9);
		b = a;
		a = tt1;

		h = g;
		g = ROTATE(f, 19);
		f = e;
		e = P0(tt2);
	}


	for(j = 16; j < 33; j++)
	{
		ss1 = ROTATE(ROTATE(a, 12) +  e + ROTATE(TL, j), 7);
		ss2 = ss1 ^ ROTATE(a, 12);
		tt1 = FFL(a, b, c) + d + ss2 + w[68 + j];
		tt2 = GGL(e, f, g) + h + ss1 + w[j];

		d = c;
		c = ROTATE(b, 9);
		b = a;
		a = tt1;

		h = g;
		g = ROTATE(f, 19);
		f = e;
		e = P0(tt2);
	}


	for(j = 33; j < 64; j++)
	{
		ss1 = ROTATE(ROTATE(a, 12) +  e + ROTATE(TL, (j-32)), 7);
		ss2 = ss1 ^ ROTATE(a, 12);
		tt1 = FFL(a, b, c) + d + ss2 + w[68 + j];
		tt2 = GGL(e, f, g) + h + ss1 + w[j];

		d = c;
		c = ROTATE(b, 9);
		b = a;
		a = tt1;

		h = g;
		g = ROTATE(f, 19);
		f = e;
		e = P0(tt2);
	}


	ctx->h[0]  ^=  a ;
	ctx->h[1]  ^=  b ;
	ctx->h[2]  ^=  c ;
	ctx->h[3]  ^=  d ;
	ctx->h[4]  ^=  e ;
	ctx->h[5]  ^=  f ;
	ctx->h[6]  ^=  g ;
	ctx->h[7]  ^=  h ;

}


void SM3_Init (SM3_CTX *ctx)
{
	ctx->h[0] = 0x7380166fUL;
	ctx->h[1] = 0x4914b2b9UL;
	ctx->h[2] = 0x172442d7UL;
	ctx->h[3] = 0xda8a0600UL;
	ctx->h[4] = 0xa96f30bcUL;
	ctx->h[5] = 0x163138aaUL;
	ctx->h[6] = 0xe38dee4dUL;
	ctx->h[7] = 0xb0fb0e4eUL;
	ctx->Nl   = 0;
	ctx->Nh   = 0;
	ctx->num  = 0;
}

void SM3_Update(SM3_CTX *ctx, const void *data, int len)
{
	unsigned char *d;
	unsigned int l;
	int i, sw, sc;


	if (len == 0)
		return;

	l = (ctx->Nl + (len << 3)) & 0xffffffffL;
	if (l < ctx->Nl) /* overflow */
		ctx->Nh++;
	ctx->Nh += (len >> 29);
	ctx->Nl = l;


	d = (unsigned char *)data;

	while (len >= SM3_CBLOCK)
	{
		ctx->data[0] = c_2_nl(d);
		d += 4;
		ctx->data[1] = c_2_nl(d);
		d += 4;
		ctx->data[2] = c_2_nl(d);
		d += 4;
		ctx->data[3] = c_2_nl(d);
		d += 4;
		ctx->data[4] = c_2_nl(d);
		d += 4;
		ctx->data[5] = c_2_nl(d);
		d += 4;
		ctx->data[6] = c_2_nl(d);
		d += 4;
		ctx->data[7] = c_2_nl(d);
		d += 4;
		ctx->data[8] = c_2_nl(d);
		d += 4;
		ctx->data[9] = c_2_nl(d);
		d += 4;
		ctx->data[10] = c_2_nl(d);
		d += 4;
		ctx->data[11] = c_2_nl(d);
		d += 4;
		ctx->data[12] = c_2_nl(d);
		d += 4;
		ctx->data[13] = c_2_nl(d);
		d += 4;
		ctx->data[14] = c_2_nl(d);
		d += 4;
		ctx->data[15] = c_2_nl(d);
		d += 4;

		sm3_block(ctx);
		len -= SM3_CBLOCK;
	}

	if(len > 0)
	{
		memset(ctx->data, 0, 64);
		ctx->num = len + 1;
		sw = len >> 2;
		sc = len & 0x3;

		for(i = 0; i < sw; i++)
		{
			ctx->data[i] = c_2_nl(d);
			d += 4;
		}

		switch(sc)
		{
			case 0:
				ctx->data[i] = 0x80000000;
				break;
			case 1:
				ctx->data[i] = (d[0] << 24) | 0x800000;
				break;
			case 2:
				ctx->data[i] = (d[0] << 24) | (d[1] << 16) | 0x8000;
				break;
			case 3:
				ctx->data[i] = (d[0] << 24) | (d[1] << 16) | (d[2] << 8) | 0x80;
				break;
		}

	}


}

void SM3_Final(unsigned char *md, SM3_CTX *ctx)
{

	if(ctx->num == 0)
	{
		memset(ctx->data, 0, 64);
		ctx->data[0] = 0x80000000;
		ctx->data[14] = ctx->Nh;
		ctx->data[15] = ctx->Nl;
	}
	else
	{
		if(ctx->num <= SM3_LAST_BLOCK)
		{
			ctx->data[14] = ctx->Nh;
			ctx->data[15] = ctx->Nl;
		}
		else
		{
			sm3_block(ctx);
			memset(ctx->data, 0, 56);
			ctx->data[14] = ctx->Nh;
			ctx->data[15] = ctx->Nl;
		}
	}

	sm3_block(ctx);

	nl2c(ctx->h[0], md);
	nl2c(ctx->h[1], md);
	nl2c(ctx->h[2], md);
	nl2c(ctx->h[3], md);
	nl2c(ctx->h[4], md);
	nl2c(ctx->h[5], md);
	nl2c(ctx->h[6], md);
	nl2c(ctx->h[7], md);
}

unsigned char *sm3(const unsigned char *data, int datalen, unsigned char *digest)
{
/*
���ܣ�    ��SM3�㷨��ժҪ

����˵����
		data     [����] ������ժҪ������
		datalen  [����] data���ֽ���
		digest   [���] 32�ֽڵ�ժҪֵ

����ֵ��ָ��digest��ָ��

*/	
	
	SM3_CTX ctx;

	SM3_Init(&ctx);
	SM3_Update(&ctx, data, datalen);
	SM3_Final(digest, &ctx);
	memset(&ctx, 0, sizeof(ctx));

	return(digest);
}


unsigned char *sm3_hmac(unsigned char *key, int keylen, unsigned char *text, int textlen, unsigned char *hmac)
{
/*
���ܣ�    ��SM3�㷨��HMAC

����˵����
		key      [����] ������HMAC����Կ
		keylen   [����] key���ֽ���
		text     [����] ������HMAC������
		textlen  [����] text���ֽ���
		hmac     [���] 32�ֽڵ�HMACֵ

����ֵ��ָ��hmac��ָ��

*/	
	
/*
ɢ����Ϣ�����룬���HMAC����һ�ֻ�����Ϣ������MAC��Message Authentication Code���ļ�����ơ�
ʹ��HMACʱ����ϢͨѶ��˫����ͨ����֤��Ϣ�м���ļ�����ԿK��������Ϣ����α��
HMAC��������һ��ɢ�к���H������Ϣ���м��ܣ���һ��ȷ����Ϣ����İ�ȫ�Ժ���Ч�ԡ�

HMAC���¶��壺
	H: ������ɢ�к������˴�ΪSM3��;
	K: ��Կ���˴���ԿΪ32�ֽ�������Կ��
	B�����ݿ���ֳ���SM3�㷨�����ݿ�ĳ���Ϊ64BYTE��
	L: ɢ�к�������������ֽڳ��ȣ�SM3��L=32��
	Text: �������Ϣ���˴�Ϊ��ǰʱ����Բ����õ��Ľ���������ǵ�ǰʱ����Բ���������ս��Ϣ��

	��ԿK�ĳ��ȿ�����С�ڵ������ݿ��ֳ���������ֵ��K�ĳ������Ǳ�B��������ʹ��ɢ�к���H����������
	Ȼ����H�����L�����ַ�����Ϊ��HMAC��ʵ��ʹ�õ���Կ��һ������£��Ƽ�����С��ԿK������L���ֳ�������H��������ݳ�����ȣ���

	���������̶��Ҳ�ͬ���ַ���ipad,opad��'i','o'��־�ڲ����ⲿ��
		ipad =ֵΪ0x36��B��bytes
		opad =ֵΪ0x5C��B��bytes.

����'text'��HMAC��

        HMAC(K,Text)=H( K XOR opad, H(K XOR ipad, Text))	 	��ʽ-2��

��ϸ���㷨�������£�
(1) ����ԿK�������0������һ���ֳ�ΪB���ַ�����(���磬���K���ֳ���32�ֽڣ�B��64�ֽڣ���K������32�����ֽ�0x00)
(2)	����һ�����ɵ�B�ֳ����ַ�����ipad��������㡣
(3)	��������text������ڶ����Ľ���ַ����С�

(4)	��H�����ڵ��������ɵ���������
(5)	����һ�����ɵ�B�ֳ��ַ�����opad��������㡣
(6)	�ٽ����Ĳ��Ľ���������岽�Ľ���С�
(7)	��H�����ڵ��������ɵ���������������ս��

*/

	unsigned char keypaded[64];
	unsigned char *p;
	int i;

//#1
	memset(keypaded, 0, sizeof(keypaded));
	if(keylen > 64)
	{
		sm3(key, keylen, keypaded);
	}
	else
	{
		memcpy(keypaded, key, keylen);
	}

//#2

	p = malloc(64 + textlen + 32);
	if( NULL == p)
		return NULL;

	for(i = 0; i < 64; i++)
		p[i] = keypaded[i] ^ 0x36;
//#3

	memcpy(p + 64, text, textlen);

//#4
	sm3(p, 64 + textlen, hmac);

//#5
	for(i = 0; i < 64; i++)
		p[i] = keypaded[i] ^ 0x5C;

//#6
	memcpy(p + 64, hmac, 32);

//#7
	sm3(p, 64 + 32, hmac);


	free(p);

	return hmac;

}


#if DEBUG_SM3

int main()
{
	unsigned char data[] = "abc";
	/*66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0*/
	unsigned char data1[] = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
	/*debe9ff9 2275b8a1 38604889 c18e5a4d 6fdb70e5 387e5765 293dcba3 9c0c5732*/
	unsigned char md[SM3_DIGEST_LENGTH];

	clock_t start,end;
	double tt;
	int j;


	unsigned char key[]="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

	sm3_hmac(key, 65, data, strlen(data), md);
#if DEBUG_SM3
	PrintBuf(md, 32);
#endif

	memset(md, 0, sizeof(md));
	sm3(data, 3, md);
#if DEBUG_SM3
	PrintBuf(md, 32);
#endif

	memset(md, 0, sizeof(md));
	sm3(data1, 64, md);
#if DEBUG_SM3
	PrintBuf(md, 32);
#endif

	start = clock();

	for(j=0;j<1000000;j++)
	{
		sm3(data1, 55, md);
	}


	end = clock();

	tt = (double)(end-start)/CLOCKS_PER_SEC;
	printf("speed:%lfMbps\n", (double)512/tt);

	return 0;
}
#endif

