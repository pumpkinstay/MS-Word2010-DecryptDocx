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

ʹ��˵����
1. ������Ҫ���ܵ�office 2010 word�ļ��ĺ�׺.docx Ϊ.rar���� XXX.docx ��� XXX.rar��
2. �ý�ѹ�����ѹ.rar
3. �ѽ�ѹ���EncryptionInfo�ļ��ŵ��ó���Ŀ¼��
4. ����DecryptDocx.exe  ������ʾ����EncryptionInfo
5. ������ʾ�ֱ�������Ļ����ʾ��readline 27-29�е���Ϣ
6. ������ϣ�������ܺ����λ���� code= ...


