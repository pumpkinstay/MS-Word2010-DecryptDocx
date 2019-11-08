/*
* Copyright(C),2018 ZJU
* FileName:  DecryptDocx.c
* Author: 	WuJiangNan
* Version:  1st
* Date:  2018/11/13
*
*Descriptions: 
	程序对 Microsoft office 2010版本的docx格式的文档进行解密
	密码由3个数字组成，from “000” to “999”. 
	
	Input   : 文件名EncryptionInfo 
	Output  : EncryptionInfo里的所有信息 
	
	Input   : EncryptionInfo里面解密所需信息
				——saltValue(the 2nd one)
				——encryptedVerifierHashInput
				——encryptedVerifierHashValue 
	Output  : Base64解码后的信息(16进制)
	
	Return  : 解密后的3位密码 
	
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
	
	
/*			提取EncryptionInfo的信息并输出		*/
	ReadInfo(1); 	//用户输入EncryptionInfo 


/*			用户输出解密所需信息		*/
	getchar();
	printf("\n\nplease input the saltValue:  \n");
	gets(salt_base64); 
	printf("\nplease input the encryptedVerifierHashInput:  \n");
	gets(VerInput_base64); 
	printf("\nplease input the encryptedVerifierHashValue:  \n");
	gets(VerValue_base64);
	puts("\n");
	
/*		    对所需info进行base64解码   		*/ 

	// 解码得到char类型salt_char、VerInput_char... 
 	base64_decode( salt_base64, salt_char ); //saltValue进行salt_base64解码 
 	base64_decode( VerInput_base64, VerInput_char ); 
 	base64_decode( VerValue_base64, VerValue_char ); 
	
	
	//char类型转u32 
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
	
	
	//解码后的信息 输出 
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

    // 参数定义
	u32 pwd;			  //密码 password 
	u32 mid,left,right;       //密码的左中右 数字 	 
	int equal;           // 最终比较Verifier相等与否 
	 
	u32 w0[4],w1[4],w2[4],w3[4],digest[5]; 
	u32 H0[5],H1[5];				  // 摘要 
    const u32 H[5]={SHA1M_A,SHA1M_B,SHA1M_C,SHA1M_D,SHA1M_E};  //SHA1算法的初始化常量  	
 	

	// 10,0000次SHA1迭代 参数定义 
	u32 loop;    //当前迭代次数
	u32 a,b,c,d; 

	// AES密钥扩展 参数定义 
	u32 rkey1[4],rkey2[4];    
	u32 k1[44],k2[44];   	 // 4*4*11 Byte 
	
	// AES加解密 参数定义
	u32 mVerifier[4],mVerifier_2[4],mVerifierHash[4],VerifierFinal[4];
	u32 out[4]={0,0,0,0};    //初始化 
	u32 in[4];
	u32 rdk[4],rek[4]; 

/***————————pwd  000-999循环————————***/
	for(pwd=0;pwd<999;pwd++){
	
/*  		salt + pwd 拼接, SHA1扩展分组   		  */ 

 		right=pwd%10+48;		  	  
 		mid=(pwd/10)%10+48;  	  
		left= pwd/100+48;    	 // pwd为utf-16编码 
		
		memcpy(w0,salt,16); 	  
 		w1[0]=(left<<24)+(mid<<8);
		w1[1]=(right<<24)+(1<<15); 
		w1[2]=w1[3]=0; 
 		memset(w2,0,16);
		memset(w3,0,16);
		w3[3]=176;          //SHA1补位规则: 最后补上消息长度 
		memcpy(digest,H,20);			//初始化digest 	
		
/*		  一轮SHA1计算得到摘要H0		*/ 	
	 	sha1_transform (w0,w1,w2,w3,digest); 
	 	memcpy(H0,digest,20);  		
	/*
	// 输出H0 
		puts("H0=");
		for(j=0;j<5;j++){
		printf("%x  ",H0[j]);
		}
		puts("\n");*/

/*		  H0进行10万次SHA1迭代  得H1		*/	
		
		//对一些不变参量的赋值 
	 	memset(w1,0,16);
	 	memset(w2,0,16);
	 	memset(w3,0,16);
	 	w1[2]=1<<31;
	 	w3[3]=192;
	 	
	 	// 10,0000循环 
		for(m=0;m<100000;m++){
			loop=m;
		//高低字节交换
			a=(loop>>24)&0x000000ff;
			b=(loop>>8)&0x0000ff00;
			c=(loop<<8)&0x00ff0000;
			d=(loop<<24)&0xff000000;
			loop=a|b|c|d;
			w0[0]=loop; w0[1]=digest[0];  w0[2]=digest[1];  w0[3]=digest[2];		
	 		w1[0]=digest[3];  w1[1]=digest[4];
			memcpy(digest,H,20);  //	初始化digest
	
	 		sha1_transform (w0,w1,w2,w3,digest); 
		} 
		memcpy(H1,digest,20);     // 得到摘要H1 
	
		// 输出H1 
		/*
		puts("H1=");
		for(j=0;j<5;j++){
		printf("%x  ",H1[j]);
		}
		puts("\n");	*/
		
/*		  H1与两个BlockKey生成rkey1/rkey2		*/	

		// SHA1 得到rkey1 
	 	memcpy(w0,H1,16);		
	 	w1[0]=H1[4];
		w1[1]=encryptedVerifierHashInputBlockKey[0];
		w1[2]=encryptedVerifierHashInputBlockKey[1]; 
		w1[3]=1<<31;
	 	memset(w2,0,16);
	 	memset(w3,0,16);
	 	w3[3]=224;     //消息长度160+64=224bit 
		memcpy(digest,H,20);	   
		sha1_transform (w0,w1,w2,w3,digest);  
		memcpy(rkey1,digest,16);   //rkey1取SHA1输出的前128bit 
	/*
		puts("rkey1=");
		for(j=0;j<4;j++){
		printf("%x  ",rkey1[j]);
		}
		puts("\n"); */
		
		
	 	// SHA1 得到rkey2 	
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
		
/*		rkey1/2  AES密钥扩展  得扩展密钥k1,k2		*/	
		AES128_ExpandKey (rkey2,k2,te0,te1,te2,te3,te4);
		AES128_ExpandKey (rkey1,k1,te0,te1,te2,te3,te4);
		AES128_InvertKey (k1,td0,td1,td2,td3,td4,te0,te1,te2,te3,te4);


/*		k1对明文VerifierHashInput进行AES解密得mVerifier		*/
		

		
		AES128_decrypt (VerInput,mVerifier,k1,td0,td1,td2,td3,td4);
	/*
		puts("mVerifier=");
		for(j=0;j<4;j++){
		printf("%x  ",mVerifier[j]);
		}
		puts("\n");*/
		
/*		mVerifier SHA1 得 mVerifierHash		*/	
		for(j=0;j<4;j++)	mVerifier_2[j]=mVerifier[j]^salt[j];
		memcpy(w0,mVerifier_2,16);
		memset(w1,0,16);
		w1[0]=1<<31;
		memset(w2,0,16);
		memset(w3,0,16);
		w3[3]=128;     //消息长度128bit 
		memcpy(digest,H,20);
		sha1_transform (w0,w1,w2,w3,digest); 
		memcpy(mVerifierHash,digest,16);
		
		/*
		puts("mVerifierHash=");	
		for(j=0;j<4;j++){
		printf("%x  ",mVerifierHash[j]);
		}
		puts("\n"); */
		
/*		k2对mVerifierHash加密得最终VerifierFinal	 */	
		for(j=0;j<4;j++)	mVerifierHash[j]=mVerifierHash[j]^salt[j];
		AES128_encrypt(mVerifierHash,VerifierFinal,k2,te0,te1,te2,te3,te4);
	/* 
		puts("VerifierFinal=");
		for(j=0;j<4;j++){
		printf("%x  ",VerifierFinal[j]);
		}
		puts("\n");*/
		
		
/*		判断两个Verifier是否相等	 */		
		equal=1;           // 判断标志 
		for(j=0;j<4;j++){
			if(VerifierFinal[j]==VerValue[j]) ;
			else {
				equal=0;break;
			}
		}
		if(equal==1) {    
		printf("\ncode=%d%d%d\n",pwd/100,(pwd/10)%10,pwd%10);  //相等则输出 
		break;
		}
	
	}	

} 

/*		读取文件 输出文件内容		*/
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
	
	// 将光标停在文件的末尾
	fseek (fp , 0 , SEEK_END);
	//返回文件的大小（单位是bytes）
	lSize = ftell (fp);
	//将光标重新移回文件的开头
	rewind (fp);
	//将文件的内容读取到buffer中 
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
