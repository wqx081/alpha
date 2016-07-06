#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "miracl.h"
#include "sm2.h"
#include "sm4.h"
//#include "mxpci_spi.h"


#define ECCref_MAX_BITS     256 
#define ECCref_MAX_LEN      ((ECCref_MAX_BITS+7) / 8)
typedef struct ECCrefPublicKey_st
{
	unsigned int  bits;
	unsigned char x[ECCref_MAX_LEN];
	unsigned char y[ECCref_MAX_LEN]; 
} ECCrefPublicKey;

typedef struct ECCrefPrivateKey_st
{
	unsigned int  bits;
	unsigned char D[ECCref_MAX_LEN];
} ECCrefPrivateKey;

/*
���ܣ�����SM2��˽Կ��
[���] pubkey : �����Կ
[���] privkey: ���˽Կ
*/
int alo_getKeypair(ECCrefPublicKey pubkey,ECCrefPrivateKey privkey);

/*
���ܣ���SM2��Կ�������ݡ����ܽ�����������ݶ�96�ֽڣ�
[����] msg     Ҫ���ܵ�����
[����] msglen��msg���ֽ���
[����] pubkey ���빫Կ

[���] outmsg: ���ܽ�������������ݶ�96�ֽ�

����ֵ��
		-1��        ����ʧ��
		msglen+96�� ���ܳɹ�
*/
int alo_ECCencrpyt(unsigned char *msg, int msglen, ECCrefPublicKey pubkey ,unsigned char *outmsg);

/*
���ܣ���SM2˽Կ�������ݡ����ܽ��������������96�ֽڣ�
[����] msg     Ҫ���ܵ����ݣ�������96�ֽڡ�
[����] msglen��msg���ֽ���
[����] privkey�� ˽Կ
[����] privkeylen�� privkeylen���ֽ���

[���] outmsg: ���ܽ����������������96�ֽڣ�

����ֵ��
		-1��        ����ʧ��
		msglen-96�� ���ܳɹ�
*/
int alo_ECCdecrypt(unsigned char *msg, int msglen, ECCrefPrivateKey privkey, unsigned char *outmsg);

/*
in:        Ҫ���ܻ���ܵ����ݣ��������SM4_BLOCK_SIZE���������������Զ���0x00���롣
out:       ����Ľ������SM4_BLOCK_SIZE��������
length:    in���ֽ���
key:       16 �ֽڵ��û���Կ
enc:       ���ܻ���ܣ�SM4_ENCRYPT/SM4_DECRYPT
*/
void alo_ECBencrpyt(const U8 *in, U8 *out,const U32 length, const U8 *key,const U32 enc);