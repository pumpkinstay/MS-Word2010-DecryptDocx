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

使用说明：
1. 更改需要解密的office 2010 word文件的后缀.docx 为.rar（从 XXX.docx 变成 XXX.rar）
2. 用解压软件解压.rar
3. 把解压后的EncryptionInfo文件放到该程序目录下
4. 运行DecryptDocx.exe  根据提示输入EncryptionInfo
5. 根据提示分别输入屏幕上显示的readline 27-29行的信息
6. 运行完毕，输出解密后的三位密码 code= ...


