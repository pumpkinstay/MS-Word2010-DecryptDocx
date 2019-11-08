/**
* Copyright(C),2018 ZJU
* FileName:  Base64_decode.h
* Author: 	WuJiangNan
* Version: 1st
* Date:  2018/11/13
*
* Function List:   //主要函数列表，每条记录应包含函数名及功能简要说明
*    1.int base64_decode( const char * base64, unsigned char * bindata ) 
 
*		 base64解码：输入纯文本的base64编码
*  				     输出原来的二进制流
*
*	 	  解码过程 
* 		  c z E z
* 	 	 对应ASCII值为 99 122 69 122
*  		 对应表base64_suffix_map的值为 28 51 4 51
*  		 对应二进制值为 00011100 00110011 00000100 00110011
*  		 依次去除每组的前两位, 再拼接成3字节
*  		 即: 01110011 00110001 00110011
*  		 对应的就是s 1 3
*/

#ifndef Base64_decode_h
#define Base64_decode_h

#include <stdio.h>

    int base64_decode( const char * base64, unsigned char * bindata );
            

#endif

