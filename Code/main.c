/*
* Copyright(C),2018 ZJU
* FileName:  DecryptDocx.c
* Author: 	WuJiangNan
* Version:  1st
* Date:  2018/11/13
*
*Descriptions: 
	����� Microsoft office 2010�汾��docx��ʽ���ĵ����н���
	������3��������ɣ�from ��000�� to ��999��. 
	
	Input   : �ļ���EncryptionInfo 
	Output  : EncryptionInfo���������Ϣ 
	
	Input   : EncryptionInfo�������������Ϣ
				����saltValue(the 2nd one)
				����encryptedVerifierHashInput
				����encryptedVerifierHashValue 
	Output  : Base64��������Ϣ(16����)
	
	Return  : ���ܺ��3λ���� 
	
*/


#include <memory.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>
#include "hash_func.h"
#include "AES128.h"
#include "Base64_decode.h"

typedef unsigned int u32;

void ReadInfo();
void AES128_ExpandKey (u32 *userkey, u32 *rek, u32 *s_te0, u32 *s_te1, u32 *s_te2, u32 *s_te3, u32 *s_te4);
void AES128_InvertKey (u32 *rdk, u32 *s_td0, u32 *s_td1, u32 *s_td2, u32 *s_td3, u32 *s_td4, u32 *s_te0, u32 *s_te1, u32 *s_te2, u32 *s_te3, u32 *s_te4);
void AES128_decrypt (const u32 *in, u32 *out, const u32 *rdk, u32 *s_td0, u32 *s_td1, u32 *s_td2, u32 *s_td3, u32 *s_td4);
void AES128_encrypt (const u32 *in, u32 *out, const u32 *rek, u32 *s_te0, u32 *s_te1, u32 *s_te2, u32 *s_te3, u32 *s_te4);
  
void main(){
	
	u32 i,j,k,m;
 	unsigned char salt_base64[30],salt_char[20];
 	unsigned char VerInput_base64[60],VerInput_char[40];
 	unsigned char VerValue_base64[60],VerValue_char[40];
	u32 salt[4],VerInput[4],VerValue[8];
	
	
/*			��ȡEncryptionInfo����Ϣ�����		*/
	ReadInfo(1); 	//�û�����EncryptionInfo 


/*			�û��������������Ϣ		*/
	getchar();
	printf("\n\nplease input the saltValue:  \n");
	gets(salt_base64); 
	printf("\nplease input the encryptedVerifierHashInput:  \n");
	gets(VerInput_base64); 
	printf("\nplease input the encryptedVerifierHashValue:  \n");
	gets(VerValue_base64);
	puts("\n");
	
/*		    ������info����base64����   		*/ 

	// ����õ�char����salt_char��VerInput_char... 
 	base64_decode( salt_base64, salt_char ); //saltValue����salt_base64���� 
 	base64_decode( VerInput_base64, VerInput_char ); 
 	base64_decode( VerValue_base64, VerValue_char ); 
	
	
	//char����תu32 
    i=0;
	for(k=0;k<4;k++){
	salt[k]=(salt_char[i]<<24)+(salt_char[i+1]<<16)+(salt_char[i+2]<<8)+(salt_char[i+3]);
	
	VerInput[k]=(VerInput_char[i]<<24)+(VerInput_char[i+1]<<16)
				 +(VerInput_char[i+2]<<8)+(VerInput_char[i+3]);
	i+=4;
	}	
	
	i=0;
	for(k=0;k<8;k++){
	VerValue[k]=(VerValue_char[i]<<24)+(VerValue_char[i+1]<<16)
				+(VerValue_char[i+2]<<8)+(VerValue_char[i+3]);
	i+=4;
	}
	
	
	//��������Ϣ ��� 
	puts("salt=");
	for(j=0;j<4;j++){
	printf("%x  ",salt[j]);
	}
	puts("\n"); 	
	
	puts("VerInput=");
	for(j=0;j<4;j++){
	printf("%x  ",VerInput[j]);
	}
	puts("\n"); 	
	
	puts("VerValue=");
	for(j=0;j<8;j++){
	printf("%x  ",VerValue[j]);
	}
	puts("\n"); 	

    // ��������
	u32 pwd;			  //���� password 
	u32 mid,left,right;       //����������� ���� 	 
	int equal;           // ���ձȽ�Verifier������ 
	 
	u32 w0[4],w1[4],w2[4],w3[4],digest[5]; 
	u32 H0[5],H1[5];				  // ժҪ 
    const u32 H[5]={SHA1M_A,SHA1M_B,SHA1M_C,SHA1M_D,SHA1M_E};  //SHA1�㷨�ĳ�ʼ������  	
 	

	// 10,0000��SHA1���� �������� 
	u32 loop;    //��ǰ��������
	u32 a,b,c,d; 

	// AES��Կ��չ �������� 
	u32 rkey1[4],rkey2[4];    
	u32 k1[44],k2[44];   	 // 4*4*11 Byte 
	
	// AES�ӽ��� ��������
	u32 mVerifier[4],mVerifier_2[4],mVerifierHash[4],VerifierFinal[4];
	u32 out[4]={0,0,0,0};    //��ʼ�� 
	u32 in[4];
	u32 rdk[4],rek[4]; 

/***����������������pwd  000-999ѭ������������������***/
	for(pwd=0;pwd<999;pwd++){
	
/*  		salt + pwd ƴ��, SHA1��չ����   		  */ 

 		right=pwd%10+48;		  	  
 		mid=(pwd/10)%10+48;  	  
		left= pwd/100+48;    	 // pwdΪutf-16���� 
		
		memcpy(w0,salt,16); 	  
 		w1[0]=(left<<24)+(mid<<8);
		w1[1]=(right<<24)+(1<<15); 
		w1[2]=w1[3]=0; 
 		memset(w2,0,16);
		memset(w3,0,16);
		w3[3]=176;          //SHA1��λ����: �������Ϣ���� 
		memcpy(digest,H,20);			//��ʼ��digest 	
		
/*		  һ��SHA1����õ�ժҪH0		*/ 	
	 	sha1_transform (w0,w1,w2,w3,digest); 
	 	memcpy(H0,digest,20);  		
	/*
	// ���H0 
		puts("H0=");
		for(j=0;j<5;j++){
		printf("%x  ",H0[j]);
		}
		puts("\n");*/

/*		  H0����10���SHA1����  ��H1		*/	
		
		//��һЩ��������ĸ�ֵ 
	 	memset(w1,0,16);
	 	memset(w2,0,16);
	 	memset(w3,0,16);
	 	w1[2]=1<<31;
	 	w3[3]=192;
	 	
	 	// 10,0000ѭ�� 
		for(m=0;m<100000;m++){
			loop=m;
		//�ߵ��ֽڽ���
			a=(loop>>24)&0x000000ff;
			b=(loop>>8)&0x0000ff00;
			c=(loop<<8)&0x00ff0000;
			d=(loop<<24)&0xff000000;
			loop=a|b|c|d;
			w0[0]=loop; w0[1]=digest[0];  w0[2]=digest[1];  w0[3]=digest[2];		
	 		w1[0]=digest[3];  w1[1]=digest[4];
			memcpy(digest,H,20);  //	��ʼ��digest
	
	 		sha1_transform (w0,w1,w2,w3,digest); 
		} 
		memcpy(H1,digest,20);     // �õ�ժҪH1 
	
		// ���H1 
		/*
		puts("H1=");
		for(j=0;j<5;j++){
		printf("%x  ",H1[j]);
		}
		puts("\n");	*/
		
/*		  H1������BlockKey����rkey1/rkey2		*/	

		// SHA1 �õ�rkey1 
	 	memcpy(w0,H1,16);		
	 	w1[0]=H1[4];
		w1[1]=encryptedVerifierHashInputBlockKey[0];
		w1[2]=encryptedVerifierHashInputBlockKey[1]; 
		w1[3]=1<<31;
	 	memset(w2,0,16);
	 	memset(w3,0,16);
	 	w3[3]=224;     //��Ϣ����160+64=224bit 
		memcpy(digest,H,20);	   
		sha1_transform (w0,w1,w2,w3,digest);  
		memcpy(rkey1,digest,16);   //rkey1ȡSHA1�����ǰ128bit 
	/*
		puts("rkey1=");
		for(j=0;j<4;j++){
		printf("%x  ",rkey1[j]);
		}
		puts("\n"); */
		
		
	 	// SHA1 �õ�rkey2 	
		w1[1]=encryptedVerifierHashValueBlockKey[0];
		w1[2]=encryptedVerifierHashValueBlockKey[1]; 
		memcpy(digest,H,20);	
		sha1_transform (w0,w1,w2,w3,digest);  		 
		memcpy(rkey2,digest,16);
	
	/*
		puts("rkey2=");
		for(j=0;j<4;j++){
		printf("%x  ",rkey2[j]);
		}
		puts("\n"); */
		
/*		rkey1/2  AES��Կ��չ  ����չ��Կk1,k2		*/	
		AES128_ExpandKey (rkey2,k2,te0,te1,te2,te3,te4);
		AES128_ExpandKey (rkey1,k1,te0,te1,te2,te3,te4);
		AES128_InvertKey (k1,td0,td1,td2,td3,td4,te0,te1,te2,te3,te4);


/*		k1������VerifierHashInput����AES���ܵ�mVerifier		*/
		

		
		AES128_decrypt (VerInput,mVerifier,k1,td0,td1,td2,td3,td4);
	/*
		puts("mVerifier=");
		for(j=0;j<4;j++){
		printf("%x  ",mVerifier[j]);
		}
		puts("\n");*/
		
/*		mVerifier SHA1 �� mVerifierHash		*/	
		for(j=0;j<4;j++)	mVerifier_2[j]=mVerifier[j]^salt[j];
		memcpy(w0,mVerifier_2,16);
		memset(w1,0,16);
		w1[0]=1<<31;
		memset(w2,0,16);
		memset(w3,0,16);
		w3[3]=128;     //��Ϣ����128bit 
		memcpy(digest,H,20);
		sha1_transform (w0,w1,w2,w3,digest); 
		memcpy(mVerifierHash,digest,16);
		
		/*
		puts("mVerifierHash=");	
		for(j=0;j<4;j++){
		printf("%x  ",mVerifierHash[j]);
		}
		puts("\n"); */
		
/*		k2��mVerifierHash���ܵ�����VerifierFinal	 */	
		for(j=0;j<4;j++)	mVerifierHash[j]=mVerifierHash[j]^salt[j];
		AES128_encrypt(mVerifierHash,VerifierFinal,k2,te0,te1,te2,te3,te4);
	/* 
		puts("VerifierFinal=");
		for(j=0;j<4;j++){
		printf("%x  ",VerifierFinal[j]);
		}
		puts("\n");*/
		
		
/*		�ж�����Verifier�Ƿ����	 */		
		equal=1;           // �жϱ�־ 
		for(j=0;j<4;j++){
			if(VerifierFinal[j]==VerValue[j]) ;
			else {
				equal=0;break;
			}
		}
		if(equal==1) {    
		printf("\ncode=%d%d%d\n",pwd/100,(pwd/10)%10,pwd%10);  //�������� 
		break;
		}
	
	}	

} 

/*		��ȡ�ļ� ����ļ�����		*/
 void ReadInfo(int start){
 	
	char* buffer;
	long lSize;
	FILE *fp;
	char filename[50];
	int q;
	char saltValue[50],HashInput[50],HashValue[50],tem[100];
	
	printf("please input the filename:  ");
	scanf("%s",filename);
	printf("\n");
	
	fp = fopen(filename,"r");
	if (fp==NULL) 
	{
	  printf("reading error\n");
	  exit (1);
	}
	
	// �����ͣ���ļ���ĩβ
	fseek (fp , 0 , SEEK_END);
	//�����ļ��Ĵ�С����λ��bytes��
	lSize = ftell (fp);
	//����������ƻ��ļ��Ŀ�ͷ
	rewind (fp);
	//���ļ������ݶ�ȡ��buffer�� 
	buffer = (char*)malloc(lSize);  
	rewind(fp);
	fread (buffer,1,lSize,fp);
	rewind(fp);
	int i=1;
	while(!feof(fp)){
		fscanf(fp,"%s",buffer);
		printf("readline %d: %s\n",q+1,buffer);
	q++;
	}
	fclose (fp);
}
