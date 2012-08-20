#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>
#include <semaphore.h>

#include "common.h"

/* 
���ܣ���ָ���ַ�����ָ��λ�õ��ִ�������ָ���Ľ��ƽ���ת�����õ�long������
���룺	str				����ԭʼ�ַ��������Բ������ֿ�ͷ
		str_len			����ԭʼ�ַ�������
		start_position	����ָ��ת������ʼλ�ã�ԭʼ�ַ����Ŀ�ͷλ�ö���Ϊ0
		appoint_len		����ָ����Ҫת���ĳ���
		base			����ת���Ľ��ƣ�ȡֵ��strtolһ��
�����ʧ�ܷ���-1���������صõ���long int����
*/
int appoint_str2int(char *str, unsigned int str_len, unsigned int start_position, unsigned int appoint_len, int base)
{
	if(NULL==str || str_len<(start_position+appoint_len) || appoint_len>64 || (base<0 && 36<base)){
		DEBUG("some arguments are invalid\n");
		return -1;
	}

	char tmp_str[65];
	int ret_int = 0;
	
	memset(tmp_str, 0, sizeof(tmp_str));
	strncpy(tmp_str, str+start_position, appoint_len);
	ret_int = strtol(tmp_str, NULL, base);//atoi(tmp_str);
	DEBUG("tmp_str=%s, will return with 0x%x==%d, origine str=%s, start at %d, aspect len %d\n", tmp_str,ret_int,ret_int, str, start_position, appoint_len);
	return ret_int;
}

void ms_sleep(unsigned int ms)
{
	if(ms<=0)
		return;
	struct timeval timeout;
	timeout.tv_sec=ms/1000;
	timeout.tv_usec=(ms%1000)*1000;			///ms
	select(0,NULL,NULL,NULL,&timeout);
}

unsigned int randint()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	
	srand((unsigned int)(tv.tv_usec)%10000);
	return rand();
}


/*
Ŀ¼��ʼ��������ֱ�Ӵ����ļ�ʧ�ܡ�
�����Ҫȷ������Ŀ¼������Ҫ��·�������б�ܣ��������һ����Ϊ�ļ�����
�磺filenameΪ/home/test/aaa.txt����ȷ������Ŀ¼/home/test
�磺filenameΪ/home/mydir/����ȷ������Ŀ¼/home/mydir
*/
int dir_exist_ensure(char *filename)
{
	if(NULL==filename || strlen(filename)>128){
		DEBUG("file name is NULL or too long\n");
		return -1;
	}
		
	char tmp_dir[128];
	snprintf(tmp_dir, sizeof(tmp_dir), "%s", filename);
	char *last_slash = strrchr(tmp_dir, '/');
	if(NULL==last_slash)
		return 0;
	
	*last_slash = '\0';
	
	if(0!=access(tmp_dir, F_OK)){
		ERROROUT("dir %s is not exist\n", tmp_dir);
		if(0!=mkdir(tmp_dir, 0777)){
			ERROROUT("create dir %s failed\n", tmp_dir);
			return -1;
		}
		else{
			DEBUG("create dir %s success\n", tmp_dir);
			return 0;
		}
	}
	else{
		DEBUG("dir %s is exist\n", tmp_dir);
		return 0;
	}
}

void print_timestamp(int show_s_ms, int show_str)
{
	struct timeval tv_now;
	time_t t;
	struct tm area;
	tzset(); /* tzset()*/
	
	if(show_s_ms){
		if(-1==gettimeofday(&tv_now, NULL)){
			ERROROUT("gettimeofday failed\n");
		}
		else
			printf("|s: %ld\t|ms: %ld\t|us:%ld\t", tv_now.tv_sec, (tv_now.tv_usec)/1000, (tv_now.tv_usec));
	}
	if(show_str){
		t = time(NULL);
		localtime_r(&t, &area);
		printf("|%s", asctime(&area));
	}
	
	if(0==show_str)
		printf("\n");
	
	return;
}
/*
�������������ڰ�����ִ��ʱ��ʾFloating point exception��ԭ��
�߰汾��gcc������ʱ�������µĹ�ϣ��������߶�̬���ӵ��ٶȣ����ڵͰ汾���ǲ�֧�ֵġ���˻ᷢ���������
���������
�����ӵ�ʱ�����ѡ��-Wl,--hash-style=sysv
���� gcc -Wl,--hash-type=sysv -o test test.c
http://fhqdddddd.blog.163.com/blog/static/18699154201002683914623/
--------------------------------------------------
�򵥷���:��̬����
��������� -static
g++ ....... -static

������������ʵ��ʹ��ʱ��Ч��ֻ���Լ���һ���ܼ򵥵ģ���֧������������ĺ�����

*/
int phony_div(unsigned int div_father, unsigned int div_son)
{
	if(0==div_son)
		return -1;
	
	if(0==div_father)
		return 0;
	
	int ret = 0;
	while(div_father>=div_son){
		ret ++;
		div_father -= div_son;
	}
	
	return ret;
}

/* 
����ַ���pathname���Ƿ���ָ�����ļ���filename���磺settings/allpid/allpid.xml���Ƿ���allpid.xml
��1��������ȫ�ļ���ƥ�䣬llpid.xml��Ӧ�ж�Ϊ�����ڣ�aallpid.xmlҲӦ�ж�Ϊ�����ڡ�
	2��������ȶ��ַ���ֱ�Ӿ���allpid.xml���ж�Ϊ���ڡ�
	3���ļ������������ĩβ��setting/allpid.xml/allp.xml�򲻴����ļ�allpid.xml
 */
int filename_check(const char *pathname, char *filename)
{
	if(NULL==pathname || NULL==filename){
		DEBUG("can not check filename between NULL string\n");
		return -1;
	}
	
	if(0==strcmp(pathname, filename))
		return 0;
	
	char *p_tmp = (char *)pathname;
	char *p_slash = (char *)pathname;
	int i = 0;
	int check_deadline_count = 256;
	for(i=0; i<check_deadline_count; i++){
		//DEBUG("p_tmp: %s, filename: %s, p_slash: %s\n", p_tmp, filename, p_slash);
		p_slash = strchr(p_tmp, '/');
		if(NULL==p_slash){
			p_slash = p_tmp;
			break;
		}
		else{
			p_tmp = p_slash + 1;
		}
	}
	if(i>=check_deadline_count){
		DEBUG("Shit! What a fucking string you check, it has %d slashs at least\n", check_deadline_count);
		return -1;
	}
	
	if(0==strcmp(p_slash, filename)){
		return 0;
	}
	else
		return -1;
}

/*
�������ĵ��ʮ����IPv4��ַ�Ƿ�Ϊ�Ϸ���IP��ַ��������Ƚ�����
-1���Ƿ���
0���Ϸ�
*/
int ipv4_simple_check(const char *ip_addr)
{
	if(NULL==ip_addr || 0==strlen(ip_addr))
		return -1;
	
	int ret = -1;
	int ip[4];
	if(4==sscanf(ip_addr, "%d.%d.%d.%d",&ip[0],&ip[1],&ip[2],&ip[3])){
		DEBUG("will check ip %d-%d-%d-%d\n", ip[0], ip[1], ip[2], ip[3]);
	}
	else{
		DEBUG("can NOT check %s, perhaps it has invalid format\n", ip_addr);
		return -1;
	}
	
	if((ip[0]>=0&&ip[0]<224)&&(ip[1]>=0&&ip[1]<256)&&(ip[2]>=0&&ip[2]<256)&&(ip[3]>=0&&ip[3]<256))
	{
		/*
		�ѵ�ַΪȫ���IP��ַ��ȥ
		*/
		if(ip[0]==0&&ip[1]==0&&ip[2]==0&&ip[3]==0)
			ret = -1;
		/*
		��127.0.0.0ȥ��
		*/
		else if(ip[0]==127)
			ret = -1;
		/*
		��������Ϊȫ1��ȥ��
		*/
		else if(ip[1]==255&&ip[2]==255&&ip[3]==255)
			ret = -1;
		/*
		��������Ϊȫ0��ȥ��
		*/
		else if(ip[1]==0&&ip[2]==0&&ip[3]==0)
			ret = -1;
		else
			ret = 0;
	}
	else
		ret = -1;
	
	return ret;
}
