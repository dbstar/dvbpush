/*
* example.cpp
*
*  Created on: Aug 11, 2011
*      Author: YJQ
*/

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <string.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>
#include <stdlib.h>

#include "common.h"
#include "push.h"
#include "mid_push.h"
#include "porting.h"
#include "xmlparser.h"
#include "sqlite.h"

#define MAX_PACK_LEN (1500)
#define MAX_PACK_BUF (200000)		//定义缓冲区大小，单位：包	1500*200000=280M

//static pthread_mutex_t mtx_decoder = PTHREAD_MUTEX_INITIALIZER;
//static pthread_cond_t cond_decoder = PTHREAD_COND_INITIALIZER;

#define XML_NUM			8
static char s_xml_name[XML_NUM][256];

static pthread_mutex_t mtx_xml = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond_xml = PTHREAD_COND_INITIALIZER;

//数据包结构
typedef struct tagDataBuffer
{
	short			len;
	unsigned char	buf[MAX_PACK_LEN];
}DataBuffer;

typedef struct tagPRG
{
	char		id[32];
	char		prog_uri[128];
	long long	cur;
	long long	total;
}PROG_S;

static int brand_progs_regist_init(void);

#define PROGS_NUM 32
static PROG_S s_prgs[PROGS_NUM];
static char s_push_data_dir[256];
/*************接收缓冲区定义***********/
DataBuffer *g_recvBuffer;	//[MAX_PACK_BUF]
static int g_wIndex = 0;
static int g_rIndex = 0;
/**************************************/

/*
当向push中写数据时才有必要监听进度，否则直接使用数据库中记录的进度即可。
考虑到缓冲，在无数据后多查询几轮再停止查询，因此push数据时，置此值为3。
考虑到开机最好给一次显示的机会，初始化为1。
*/
static int s_push_has_data = 0;

int send_mpe_sec_to_push_fifo(unsigned char *pkt, int pkt_len)
{
	int res = -1;
	int snap = 0;
	unsigned char *eth;
	
	static unsigned int rx_errors = 0;
	static unsigned int rx_length_errors = 0;
	static unsigned int rx_crc_errors = 0;
	static unsigned int rx_dropped = 0;
	static unsigned int rx_frame_errors = 0;
	static unsigned int rx_fifo_dropped = 0;
	
//	DEBUG("pkt_len=%d\n", pkt_len);
	if (pkt_len < 16) {
		DEBUG("IP/MPE packet length = %d too small.\n", pkt_len);
		rx_errors++;
		rx_length_errors++;
		return res;
	}
	if ((pkt[5] & 0x3c) != 0x00) {
		/* drop scrambled */
		rx_errors++;
		rx_crc_errors++;
		return res;
	}
	if (pkt[5] & 0x02) {
		if (pkt_len < 24 || memcmp(&pkt[12], "\xaa\xaa\x03\0\0\0", 6)) {
			rx_dropped++;
			return res;
		}
		snap = 8;
	}
	if (pkt[7]) {
		rx_errors++;
		rx_frame_errors++;
		return res;
	}
	if (pkt_len - 12 - 4 + 14 - snap <= 0) {
		DEBUG("IP/MPE packet length = %d too small.\n", pkt_len);
		rx_errors++;
		rx_length_errors++;
		return res;
	}
	
	//recvCount++;
	int windex = g_wIndex;
	int rindex = g_rIndex;
	
	if(0==windex%5000)
		printf("windex %d, len %d, rindex=%d\n", windex, g_recvBuffer[windex].len, rindex);
	static int s_time_pin = 0;
	int now_secs = time(NULL);
	if((now_secs-s_time_pin) >= 3){
		s_time_pin = now_secs;
		int space_count = 0;
		if(windex>rindex)
			space_count = MAX_PACK_BUF - windex + rindex;
		else if(windex==rindex){
			if((g_recvBuffer[windex].len)>0)
				space_count = 0;
			else
				space_count = MAX_PACK_BUF;
		}
		else
			space_count = rindex-windex;
			
		printf("time %ds, used %d, free %d, total %d. windex=%d, rindex=%d\n", now_secs, MAX_PACK_BUF-space_count, 
			space_count, MAX_PACK_BUF, windex, rindex);
	}
	
	if (windex==rindex && (g_recvBuffer[windex].len)>0) {
		rx_fifo_dropped++;
		if(0==(rx_fifo_dropped>>9))	// 每512次打印一次
			printf("Push FIFO is full. lost pkt count %d, windex %d, len=%d\n", rx_fifo_dropped, windex, g_recvBuffer[windex].len);
		return res;
	}
	
	eth = g_recvBuffer[windex].buf;
	
	memcpy(eth + 14, pkt + 12 + snap, pkt_len - 12 - 4 - snap);
	eth[0]=pkt[0x0b];
	eth[1]=pkt[0x0a];
	eth[2]=pkt[0x09];
	eth[3]=pkt[0x08];
	eth[4]=pkt[0x04];
	eth[5]=pkt[0x03];
	
	eth[6]=eth[7]=eth[8]=eth[9]=eth[10]=eth[11]=0;
	
	if (snap) {
		eth[12] = pkt[18];
		eth[13] = pkt[19];
	} else {
		if (pkt[12] >> 4 == 6) {
			eth[12] = 0x86;	
			eth[13] = 0xdd;
		} else {
			eth[12] = 0x08;	
			eth[13] = 0x00;
		}
	}
	
	//	memcpy(eth , pkt + 12 , pkt_len - 12 - 4 );
	g_recvBuffer[windex].len = pkt_len - 12 - 4 - snap;
	
	windex++;
	if(windex>=MAX_PACK_BUF)
		windex -= MAX_PACK_BUF;
	
	g_wIndex = windex;
	
//	pthread_mutex_lock(&mtx_decoder);
//	pthread_cond_signal(&cond_decoder); //send sianal
//	pthread_mutex_unlock(&mtx_decoder);
	
	return 0;
}

void *push_decoder_thread()
{
	unsigned char *pBuf = NULL;
	int rindex;
//	struct timeval tv_1;
//	struct timeval tv_2;
	int read_nothing_count = 0;
	
	while (1)
	{
//		pthread_mutex_lock(&mtx_decoder);
//		pthread_cond_wait(&cond_decoder,&mtx_decoder); //wait
		
		rindex = g_rIndex;
//		if(0==rindex%5000)
//			printf("rindex %d, len %d\n", rindex, g_recvBuffer[rindex].len);
		
		if (g_recvBuffer[rindex].len == 0)
		{
			usleep(20000);
			read_nothing_count++;
			if(read_nothing_count>=500)
			{
				DEBUG("read nothing, read index %d\n", rindex);
				read_nothing_count = 0;
			}
			continue;
		}
		else
		{
			pBuf = g_recvBuffer[rindex].buf;
			
			/*
			* 调用PUSH数据解析接口解析数据，该函数是阻塞的，所以应该使用一个较大
			* 的缓冲区来暂时存储源源不断的数据。
			*/
			push_parse((char *)pBuf, g_recvBuffer[rindex].len);
			s_push_has_data = 3;
			
			g_recvBuffer[rindex].len = 0;
			rindex++;
			if(rindex>=MAX_PACK_BUF)
				rindex -= MAX_PACK_BUF;
			g_rIndex = rindex;
		}
		
//		pthread_mutex_unlock(&mtx_decoder);
	}
	
	return NULL;
}

static void push_progs_finish(char *id)
{
	char sqlite_cmd[256+128];
	
	snprintf(sqlite_cmd, sizeof(sqlite_cmd), "UPDATE content SET ready=1 WHERE id='%s';", id);
	sqlite_execute(sqlite_cmd);
}

static void push_progs_process_refresh(char *regist_dir, long long cur_size)
{
	char sqlite_cmd[256+128];
	
	memset(sqlite_cmd, 0, sizeof(sqlite_cmd));
	snprintf(sqlite_cmd, sizeof(sqlite_cmd), "UPDATE brand SET download=%lld WHERE regist_dir='%s';", cur_size, regist_dir);
	sqlite_execute(sqlite_cmd);
}

/*
为避免无意义的查询硬盘，应完成下面两个工作：
1、当节目接收完毕后不应再查询，数据库中记录的是100%
2、只有UI上进入查看进度的界面后，通知底层去查询，其他时间查询没有意义。
3、当push无数据后，再轮询若干遍（等待缓冲数据写入硬盘）后就不再轮询。
*/
void *push_monitor_thread()
{
	int i;
//	struct ch_state cs[10];
	int print_count = 0;
	
	/*
	小心，反注册可能导致导致死机。但在两种情况下需要反注册：1、下发新的brand.xml；2、节目下载完毕。
	*/
	brand_progs_regist_init();
	
	sleep(1);
	
	while (1)
	{
		if(s_push_has_data>0){
			/*
			监测节目接收进度
			*/
			for(i=0;; i++)
			{
				//循环结束的条件是遇到节目路径为空串时
				if(strcmp(s_prgs[i].prog_uri, "") == 0)
				{
					break;
				}
				
				/*
				* 获取指定节目的已接收字节大小，可算出百分比
				*/
				long long rxb = push_dir_get_single(s_prgs[i].prog_uri);
				
				if(0==print_count){
					DEBUG("PROG_S:%s %s %lld/%lld %-3lld%%\n",
					s_prgs[i].id,
					s_prgs[i].prog_uri,
					rxb,
					s_prgs[i].total,
					rxb*100/s_prgs[i].total);
				}
				
				if(s_prgs[i].cur != rxb){
					push_progs_process_refresh(s_prgs[i].prog_uri, rxb);
				
					if(rxb>=s_prgs[i].total)
						push_progs_finish(s_prgs[i].id);
					
					s_prgs[i].cur = rxb;
				}
				
				if(rxb>=s_prgs[i].total){
					DEBUG("%s download finished, wipe off from monitor\n", s_prgs[i].prog_uri);
					mid_push_unregist(s_prgs[i].prog_uri);
				}
			}
			
			print_count ++;
			if(print_count>=5)
				print_count = 0;
		}
		s_push_has_data--;
		
		sleep(5);
	}
}

void *push_xml_parse_thread()
{
//	struct ch_state cs[10];
	
	while (1)
	{
		
		pthread_mutex_lock(&mtx_xml);
		pthread_cond_wait(&cond_xml,&mtx_xml); //wait
		
		int i = 0;
		for(i=0; i<XML_NUM; i++){
			if(strlen(s_xml_name[i])>0){
				parseDoc(s_xml_name[i]);
				memset(s_xml_name[i], 0, sizeof(s_xml_name[i]));
			}
		}
		
		pthread_mutex_unlock(&mtx_xml);
	}
}

void usage()
{
	printf("-i	interface name, default value is eth0.\n");
	printf("-h	print out this message.\n");
	
	printf("\n");
	exit(0);
}

int push_data_root_dir_get(char *buf, unsigned int size)
{
	if(NULL==buf || 0==size){
		DEBUG("some arguments are invalid\n");
		return -1;
	}
	
	strncpy(buf, s_push_data_dir, size);
	return 0;
}

/*
需要确保allpid.xml等关键描述文件在开机后至少解析一次。
文件更新标记flag暂时不入库，因为太频繁了，sqlite3封装的“读”接口是事务级别，比较繁琐、耗时间。
*/
void callback(const char *path, long long size, int flag)
{
	DEBUG("path:%s, size:%lld, flag:%d\n", path, size, flag);
	
	char xml_absolute_name[256+128];
	snprintf(xml_absolute_name, sizeof(xml_absolute_name), "%s/%s", s_push_data_dir, path);
	/* 由于涉及到解析和数据库操作，这里不直接调用parseDoc，避免耽误push任务的运行效率 */
	// settings/allpid/allpid.xml
	if(	0==filename_check(path, "allpid.xml")
		|| 0==filename_check(path, "column.xml")
		|| 0==filename_check(path, "ProductTag.xml")
		|| 0==filename_check(path, "brand_0001.xml")
		|| 0==filename_check(path, "PreProductTag.xml")){
			
		pthread_mutex_lock(&mtx_xml);
		
		int i = 0;
		for(i=0; i<XML_NUM; i++){
			if(0==strlen(s_xml_name[i])){
				strcpy(s_xml_name[i], xml_absolute_name);
				break;
			}
		}
		if(XML_NUM<=i)
			DEBUG("xml name space is full\n");
		else
			pthread_cond_signal(&cond_xml); //send sianal
			
		pthread_mutex_unlock(&mtx_xml);
	}
}

/*
如果传入参数为空，则寻找“/etc/push.conf”文件。详细约束参考push_init()说明
*/
static void push_root_dir_init(char *push_conf)
{
	FILE* fp = NULL;
	char tmp_buf[256];
	char *p_value;
	
	if(NULL==push_conf)
		fp = fopen("/etc/push.conf", "r");
	else
		fp = fopen(push_conf, "r");
	
	memset(s_push_data_dir, 0, sizeof(s_push_data_dir));
	if(NULL==fp){
		DEBUG("waring: open push.conf to get push data dir failed\n");
		strncpy(s_push_data_dir, PUSH_DATA_DIR_DF, sizeof(s_push_data_dir)-1);
	}
	else{
		memset(tmp_buf, 0, sizeof(tmp_buf));
		while(NULL!=fgets(tmp_buf, sizeof(tmp_buf), fp)){
			p_value = setting_item_value(tmp_buf, strlen(tmp_buf));
			if(NULL!=p_value)
			{
				DEBUG("setting item: %s, value: %s\n", tmp_buf, p_value);
				if(strlen(tmp_buf)>0 && strlen(p_value)>0){
					if(0==strcmp(tmp_buf, "DATA_DIR")){
						strncpy(s_push_data_dir, p_value, sizeof(s_push_data_dir)-1);
						break;
					}
				}
			}
			memset(tmp_buf, 0, sizeof(tmp_buf));
		}
		fclose(fp);
	}
}

static int brand_sqlite_callback(char **result, int row, int column, void *receiver)
{
	DEBUG("sqlite callback, row=%d, column=%d, receiver addr: %p\n", row, column, receiver);
	if(row<1){
		DEBUG("no record in table, return\n");
		return 0;
	}
	
	int i = 0;
	long long totalsize = 0LL;
	for(i=1;i<row+1;i++)
	{
		//DEBUG("==%s:%s:%ld==\n", result[i*column], result[i*column+1], strtol(result[i*column+1], NULL, 0));
		sscanf(result[i*column+2],"%lld", &totalsize);
		mid_push_regist(result[i*column], result[i*column+1], totalsize);
	}
	
	return 0;
}

static int brand_progs_regist_init(void)
{
	char sqlite_cmd[256+128];
	int (*sqlite_callback)(char **, int, int, void *) = brand_sqlite_callback;

	snprintf(sqlite_cmd,sizeof(sqlite_cmd),"SELECT id, regist_dir, totalsize FROM brand;");
	return sqlite_read(sqlite_cmd, NULL, sqlite_callback);
}

// "prog/file" 18816360
int mid_push_init(char *push_conf)
{
	int i = 0;
	for(i=0;i<XML_NUM;i++){
		memset(s_xml_name[i], 0, sizeof(s_xml_name[i]));
	}
	
	g_recvBuffer = (DataBuffer *)malloc(sizeof(DataBuffer)*MAX_PACK_BUF);
	if(NULL==g_recvBuffer){
		ERROROUT("can not malloc %d*%d\n", sizeof(DataBuffer), MAX_PACK_BUF);
	}
	for(i=0;i<MAX_PACK_BUF;i++)
		g_recvBuffer[i].len = 0;
	
	push_root_dir_init(push_conf);
	/*
	* 初始化PUSH库
	 */
	if (push_init(push_conf) != 0)
	{
		DEBUG("Init push lib failed!\n");
		return -1;
	}
	s_push_has_data = 1;
	
	push_set_notice_callback(callback);
	
	//创建数据解码线程
	pthread_t tidDecodeData;
	pthread_create(&tidDecodeData, NULL, push_decoder_thread, NULL);
	pthread_detach(tidDecodeData);
	
	//创建监视线程
	pthread_t tidMonitor;
	pthread_create(&tidMonitor, NULL, push_monitor_thread, NULL);
	pthread_detach(tidMonitor);
	
	//创建xml解析线程
	pthread_t tidxmlphase;
	pthread_create(&tidxmlphase, NULL, push_xml_parse_thread, NULL);
	pthread_detach(tidxmlphase);
	
	for(i=0; i<PROGS_NUM; i++){
		memset(s_prgs[i].id, 0, sizeof(s_prgs[i].id));
		memset(s_prgs[i].prog_uri, 0, sizeof(s_prgs[i].prog_uri));
		s_prgs[i].cur = 0LL;
		s_prgs[i].total = 0LL;
	}
	
#if 0	
	mid_push_regist("prog/file", 18816360LL);
	mid_push_regist("prog/video", 206237980LL);
	mid_push_regist("prog/audio", 38729433LL);
#endif
	
#if 0
	char push_file[128];
	memset(push_file, 0, sizeof(push_file));
	if(-1==root_push_file_get(push_file, sizeof(push_file)-1)){
		DEBUG("get root push file failed\n");
	}
	else{
		if(strcmp(push_file, ROOT_PUSH_FILE)){
			if(-1==mid_push_regist(push_file, root_push_file_size_get())){
				DEBUG("regist program (%s)(%d) to push failed\n", push_file, root_push_file_size_get());
				return -1;
			}
		}
	}
#endif

	return 0;
}

//注册节目
int mid_push_regist(char *id, char *content_uri, long long content_len)
{
	/*
	* Notice:节目路径是一个相对路径，不要以'/'开头；
	* 若节目单中给出的路径是"/vedios/pushvod/1944"，则去掉最开始的'/'，
	* 用"vedios/pushvod/1944"进行注册。
	*
	* 此处PRG这个结构体是出于示例方便定义的，不一定适用于您的程序中
	*/
	int i;
	for(i=0; i<PROGS_NUM; i++)
	{
		if(0==s_prgs[i].total){
			sprintf(s_prgs[i].id, "%s", id);
			sprintf(s_prgs[i].prog_uri,"%s", content_uri);
			s_prgs[i].cur = 0;
			s_prgs[i].total = content_len;
			
			push_dir_register(s_prgs[i].prog_uri, s_prgs[i].total, 0);
			DEBUG("regist to push %s %lld\n", s_prgs[i].prog_uri, s_prgs[i].total);
			break;
		}
	}
	if(i>=PROGS_NUM)
		return -1;
	else
		return 0;
}

//反注册节目
int mid_push_unregist(char *content_uri)
{
	if(NULL==content_uri || 0==strlen(content_uri))
		return -1;
	/*
	* Notice:节目路径是一个相对路径，不要以'/'开头；
	* 若节目单中给出的路径是"/vedios/pushvod/1944"，则去掉最开始的'/'，
	* 用"vedios/pushvod/1944"进行注册。
	*
	* 此处PRG这个结构体是出于示例方便定义的，不一定适用于您的程序中
	*/
	int i;
	for(i=0; i<PROGS_NUM; i++)
	{
		if(0==strcmp(s_prgs[i].prog_uri, content_uri)){
			push_dir_unregister(content_uri);
			DEBUG("unregist from push %s\n", s_prgs[i].prog_uri);
			memset(s_prgs[i].id, 0, sizeof(s_prgs[i].id));
			memset(s_prgs[i].prog_uri, 0, sizeof(s_prgs[i].prog_uri));
			s_prgs[i].cur = 0;
			s_prgs[i].total = 0;
			break;
		}
	}
	
	return 0;
}

int mid_push_uninit()
{
	push_destroy();
	return 0;
}
