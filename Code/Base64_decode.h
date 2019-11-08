/**
* Copyright(C),2018 ZJU
* FileName:  Base64_decode.h
* Author: 	WuJiangNan
* Version: 1st
* Date:  2018/11/13
*
* Function List:   //��Ҫ�����б�ÿ����¼Ӧ���������������ܼ�Ҫ˵��
*    1.int base64_decode( const char * base64, unsigned char * bindata ) 
 
*		 base64���룺���봿�ı���base64����
*  				     ���ԭ���Ķ�������
*
*	 	  ������� 
* 		  c z E z
* 	 	 ��ӦASCIIֵΪ 99 122 69 122
*  		 ��Ӧ��base64_suffix_map��ֵΪ 28 51 4 51
*  		 ��Ӧ������ֵΪ 00011100 00110011 00000100 00110011
*  		 ����ȥ��ÿ���ǰ��λ, ��ƴ�ӳ�3�ֽ�
*  		 ��: 01110011 00110001 00110011
*  		 ��Ӧ�ľ���s 1 3
*/

#ifndef Base64_decode_h
#define Base64_decode_h

#include <stdio.h>

    int base64_decode( const char * base64, unsigned char * bindata );
            

#endif

