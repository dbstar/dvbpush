/*
 * push.h
 *
 *  Created on: Jul 7, 2011
 *      Author: YJQ
 */

#ifndef PUSH_H_
#define PUSH_H_

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PATH 256
struct ch_state
{
	short chanId;			//ͨ���ţ�1~255��
	char chanName[52];		//ͨ������
	long long totalBytes;	//ͨ�������ܽ����ֽ���
	unsigned int totalOK;	//ͨ���������������ļ���
	unsigned int totalEr;	//ͨ������δ���������ļ���
	long long fileSize;	//��ǰ���ڽ��յ��ļ���С
	long long recvBytes;	//��ǰ���ڽ����ļ��ѽ����ֽ�
	char isRecover;			//0,�״ν��գ�1��ȫ����
	int rate;				//ͨ���������ʣ�Bps��
	char bak[20];			//������չ
	char fileName[MAX_PATH];//��ǰ���ڽ��յ��ļ�����
};
//����recvBytes��fileSize���Լ�����ļ�������ɰٷֱ�

struct overview
{
	long long totalBytes;	//�����ܵĽ����ֽ�����ÿ��0������
	unsigned int totalOK;	//�ܵ����������ļ���
	unsigned int totalEr;	//�ܵ�δ���������ļ���
	int recvRate;			//�������ʣ�Bps��
};

typedef void (*pfnNotice)(const char *filename, long long filesize, int fileflag);

/****************************************************************************
 *��������push_init
 *��  �ܣ���pushģ����г�ʼ���������ȵ��øú���
 *��  �룺conf_file��pushģ�������������ļ�·�������ò���ΪNULLʱ��PUSHĬ��
          ��/etc�����ȡpush.conf�ļ���Ϊ���в�������/etcĿ¼�²����ڸ��ļ���
          ��ʼ��ʧ�ܡ�
 *��  ����
 *����ֵ��0,��ʼ���ɹ���-1��ʼ��ʧ��
 ***************************************************************************/
int push_init(const char *conf_file);


/****************************************************************************
 *��������push_parse
 *��  �ܣ����ݰ�����
 *��  �룺pBuf,���ݰ���ַ; buflen,���ݰ�����
 *��  ����
 *����ֵ��0,�ɹ�����; -1,���ݰ���ʽ����; -2,����Ҫ�����ݰ�; -99,����
 ***************************************************************************/
int push_parse(char *pBuf, int buflen);


/****************************************************************************
 *��������push_set_notice_callback
 *��  �ܣ����á�information������ͨ���Ļص�����
 *��  �룺cb��pfnNotice���ͺ�����ַ
 *��  ����
 *����ֵ����
 ***************************************************************************/
void push_set_notice_callback(pfnNotice cb);


/****************************************************************************
 *��������push_get_channels
 *��  �ܣ���ȡ���е�ͨ��
 *��  �룺
 *��  ����
 *����ֵ��ͨ������
 ***************************************************************************/
int push_get_channels(short *chbuf);
int push_get_active_channels(short *chbuf);


/****************************************************************************
 *��������push_open_channel_by_id, push_open_channel_by_name
 *��  �ܣ���ͨ����ͨ���򿪺�ָ��ͨ�������ݰ�����������ͨ��Ĭ��Ϊ��״̬
 *��  �룺chid,ͨ��ID �� chname,ͨ������
 *��  ����
 *����ֵ��0,�ɹ�; ��0ʧ��
 ***************************************************************************/
int push_open_channel_by_id(short chid);
int push_open_channel_by_name(const char *chname);


/****************************************************************************
 *��������push_close_channel_by_id, push_close_channel_by_name
 *��  �ܣ��ر�ͨ������ͨ���ر�ʱ�����ٶ�ָ��ͨ�������ݰ����н���
 *��  �룺chid,ͨ��ID �� chname,ͨ������
 *��  ����
 *����ֵ��0,�ɹ�; ��0ʧ��
 ***************************************************************************/
int push_close_channel_by_id(short chid);
int push_close_channel_by_name(const char *chname);


/****************************************************************************
 *��������push_monitor_active_channels
 *��  �ܣ��Ե�ǰ���ڽ������ݵ�ͨ�����м���
 *��  �룺cs,ָ��ch_state���ͻ���������ָ��,����
 *��  ����cs,ָ��ch_state���ͻ���������ָ��,�����
 *����ֵ�����ڽ������ݵ�ͨ������
 ***************************************************************************/
int push_monitor_active_channels(struct ch_state *cs, int size);


/****************************************************************************
 *��������push_monitor_by_id, push_monitor_by_name
 *��  �ܣ�����ָ����ͨ��״̬
 *��  �룺chid,ͨ��ID �� chname,ͨ������; cs,ָ��ch_state���ͱ�����ָ��,����
 *��  ����cs,ָ��ch_state���ͱ�����ָ��,�����
 *����ֵ��0,�ɹ�; ��0ʧ��
 ***************************************************************************/
int push_monitor_by_id(short chid, struct ch_state *cs);
int push_monitor_by_name(const char *chname, struct ch_state *cs);


/****************************************************************************
 *��������push_overview
 *��  �ܣ���ȡ�ܵĽ������
 *��  �룺ov,overview���ͱ���,���ö�����
 *��  ����ov,�����
 *����ֵ����
 ***************************************************************************/
void push_overview(struct overview *ov);


/****************************************************************************
 *��������push_destroy
 *��  �ܣ��˳�
 *��  �룺
 *��  ����
 *����ֵ��
 ***************************************************************************/
void push_destroy();


/****************************************************************************
 *��������push_dir_register
 *��  �ܣ���pushע���Ŀ·��,�Ա�push�Խ�ĿĿ¼�µ����н����ļ�����ͳ��
 *��  �룺dir,��Ŀ·��,��·��Ϊ���·��,��"videos/pushvod/1944",ǰ�治Ҫ��'/';
 *        state:��Ŀ״̬,0����,-1�ѽ�ֹ,-2��ɾ��;
 *        total_bytes:��Ŀ���ֽ���
 *��  ������
 *����ֵ��0����>0��,ע��ɹ�,���з���1��ʾ֮ǰ��Ŀ�Ѵ���,���������ǣ�
 *       <0ʧ��(-1:�洢�ռ䲻��,-2:��������)
 ***************************************************************************/
int push_dir_register(const char *dir, long long total_bytes, int state);


/****************************************************************************
 *��������push_dir_unregister
 *��  �ܣ���ע�ᣨɾ������Ŀָ����·��
 *��  �룺dir,��Ŀ·��,��dirΪNULLʱ,��ʾ��ע�����еĽ�Ŀ;
 *��  ������
 *����ֵ��0,ɾ���ɹ�; -1,û�ж�Ӧ�Ľ�Ŀ·��; ����,δ֪ʧ��
 ***************************************************************************/
int push_dir_unregister(const char *dir);


/****************************************************************************
 *��������push_dir_forbid
 *��  �ܣ���ֹ���ս�Ŀ
 *��  �룺dir,��Ŀ·��
 *��  ����
 *����ֵ��0,�ѽ�ֹ; -1,δ�ҵ���Ŀ; ����,δ֪ʧ��
 ***************************************************************************/
int push_dir_forbid(const char *dir);


/****************************************************************************
 *��������push_dir_resume
 *��  �ܣ��ָ����ս�Ŀ
 *��  �룺dir,��Ŀ·��
 *��  ����
 *����ֵ��0,�ѻָ�����; -1,δ�ҵ���Ŀ; ����,δ֪ʧ��
 ***************************************************************************/
int push_dir_resume(const char *dir);

/****************************************************************************
 *��������push_dir_remove
 *��  �ܣ�ɾ��ָ����Ŀ,��Ŀ��ɾ����,�����ٽ���
 *��  �룺dir,��Ŀ·��
 *��  ����
 *����ֵ��0,�ѻָ�����; -1,δ�ҵ���Ŀ; ����,δ֪ʧ��
 ***************************************************************************/
int push_dir_remove(const char *dir);


/****************************************************************************
 *��������push_dir_get_single
 *��  �ܣ��õ�ָ����ע��Ľ�Ŀ���ѽ����ֽڴ�С
 *��  �룺dir,��Ŀ��·��
 *��  ����
 *����ֵ��long long,ָ����Ŀ���ѽ����ֽڴ�С
 ***************************************************************************/
long long push_dir_get_single(const char *dir);


/****************************************************************************
 *��������push_dir_get_all
 *��  �ܣ��õ����н�Ŀ���ѽ����ֽڴ�С
 *��  �룺dirs,�û�����,���ڴ洢��Ŀ·��;
 *        bytes,���ڴ洢��Ŀ�ѽ����ֽ���;
 *        size,ָʾ����dirs��bytes�Ĵ�С.
 *��  ����dirs,��Ŀ��·��; bytes,��Ŀ�ѽ����ֽڴ�С
 *����ֵ��ʵ�ʽ�Ŀ��
 ***************************************************************************/
int push_dir_get_all(char *dirs[], long long *bytes, int size);


#ifdef __cplusplus
}  /* End of the 'extern "C"' block */
#endif

#endif /* PUSH_H_ */