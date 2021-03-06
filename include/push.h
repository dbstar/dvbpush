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
	short chanId;			//通道号（1~255）
	char chanName[52];		//通道名称
	long long totalBytes;	//通道当天总接收字节数
	unsigned int totalOK;	//通道当天完整接收文件数
	unsigned int totalEr;	//通道当天未完整接收文件数
	long long fileSize;	//当前正在接收的文件大小
	long long recvBytes;	//当前正在接收文件已接收字节
	char isRecover;			//0,首次接收，1补全接收
	int rate;				//通道数据速率（Bps）
	char bak[20];			//用于扩展
	char fileName[MAX_PATH];//当前正在接收的文件名称
};
//根据recvBytes和fileSize可以计算出文件接收完成百分比

struct overview
{
	long long totalBytes;	//当天总的接收字节数，每天0点清零
	unsigned int totalOK;	//总的完整接收文件数
	unsigned int totalEr;	//总的未完整接收文件数
	int recvRate;			//接收速率（Bps）
};

typedef void (*pfnNotice)(const char *filename, long long filesize, int fileflag);

/****************************************************************************
 *函数名：push_init
 *功  能：对push模块进行初始化，须首先调用该函数
 *输  入：conf_file，push模块依赖的配置文件路径，当该参数为NULL时，PUSH默认
          从/etc下面读取push.conf文件作为运行参数，若/etc目录下不存在该文件，
          初始化失败。
 *输  出：
 *返回值：0,初始化成功；-1初始化失败
 ***************************************************************************/
int push_init(const char *conf_file);


/****************************************************************************
 *函数名：push_parse
 *功  能：数据包解析
 *输  入：pBuf,数据包地址; buflen,数据包长度
 *输  出：
 *返回值：0,成功解析; -1,数据包格式错误; -2,不需要的数据包; -99,其它
 ***************************************************************************/
int push_parse(char *pBuf, int buflen);


/****************************************************************************
 *函数名：push_set_notice_callback
 *功  能：设置“information”类型通道的回调函数
 *输  入：cb，pfnNotice类型函数地址
 *输  出：
 *返回值：无
 ***************************************************************************/
void push_set_notice_callback(pfnNotice cb);


/****************************************************************************
 *函数名：push_get_channels
 *功  能：获取所有的通道
 *输  入：
 *输  出：
 *返回值：通道个数
 ***************************************************************************/
int push_get_channels(short *chbuf);
int push_get_active_channels(short *chbuf);


/****************************************************************************
 *函数名：push_open_channel_by_id, push_open_channel_by_name
 *功  能：打开通道，通道打开后，指定通道的数据包将被解析，通道默认为打开状态
 *输  入：chid,通道ID 或 chname,通道名称
 *输  出：
 *返回值：0,成功; 非0失败
 ***************************************************************************/
int push_open_channel_by_id(short chid);
int push_open_channel_by_name(const char *chname);


/****************************************************************************
 *函数名：push_close_channel_by_id, push_close_channel_by_name
 *功  能：关闭通道，当通道关闭时，不再对指定通道的数据包进行解析
 *输  入：chid,通道ID 或 chname,通道名称
 *输  出：
 *返回值：0,成功; 非0失败
 ***************************************************************************/
int push_close_channel_by_id(short chid);
int push_close_channel_by_name(const char *chname);


/****************************************************************************
 *函数名：push_monitor_active_channels
 *功  能：对当前正在接收数据的通道进行监视
 *输  入：cs,指向ch_state类型缓冲区的首指针,清零
 *输  出：cs,指向ch_state类型缓冲区的首指针,被填充
 *返回值：正在接收数据的通道个数
 ***************************************************************************/
int push_monitor_active_channels(struct ch_state *cs, int size);


/****************************************************************************
 *函数名：push_monitor_by_id, push_monitor_by_name
 *功  能：监视指定的通道状态
 *输  入：chid,通道ID 或 chname,通道名称; cs,指向ch_state类型变量的指针,清零
 *输  出：cs,指向ch_state类型变量的指针,被填充
 *返回值：0,成功; 非0失败
 ***************************************************************************/
int push_monitor_by_id(short chid, struct ch_state *cs);
int push_monitor_by_name(const char *chname, struct ch_state *cs);


/****************************************************************************
 *函数名：push_overview
 *功  能：获取总的接收情况
 *输  入：ov,overview类型变量,调用都传入
 *输  出：ov,被填充
 *返回值：无
 ***************************************************************************/
void push_overview(struct overview *ov);


/****************************************************************************
 *函数名：push_destroy
 *功  能：退出
 *输  入：
 *输  出：
 *返回值：
 ***************************************************************************/
void push_destroy();


/****************************************************************************
 *函数名：push_dir_register
 *功  能：向push注册节目路径,以便push对节目目录下的所有接收文件进行统计
 *输  入：dir,节目路径,该路径为相对路径,如"videos/pushvod/1944",前面不要有'/';
 *        state:节目状态,0正常,-1已禁止,-2已删除;
 *        total_bytes:节目总字节数
 *输  出：无
 *返回值：0（或>0）,注册成功,其中返回1表示之前节目已存在,参数被覆盖；
 *       <0失败(-1:存储空间不足,-2:参数错误)
 ***************************************************************************/
int push_dir_register(const char *dir, long long total_bytes, int state);


/****************************************************************************
 *函数名：push_dir_unregister
 *功  能：反注册（删除）节目指定的路径
 *输  入：dir,节目路径,当dir为NULL时,表示反注册所有的节目;
 *输  出：无
 *返回值：0,删除成功; -1,没有对应的节目路径; 其它,未知失败
 ***************************************************************************/
int push_dir_unregister(const char *dir);


/****************************************************************************
 *函数名：push_dir_forbid
 *功  能：禁止接收节目
 *输  入：dir,节目路径
 *输  出：
 *返回值：0,已禁止; -1,未找到节目; 其它,未知失败
 ***************************************************************************/
int push_dir_forbid(const char *dir);


/****************************************************************************
 *函数名：push_dir_resume
 *功  能：恢复接收节目
 *输  入：dir,节目路径
 *输  出：
 *返回值：0,已恢复接收; -1,未找到节目; 其它,未知失败
 ***************************************************************************/
int push_dir_resume(const char *dir);

/****************************************************************************
 *函数名：push_dir_remove
 *功  能：删除指定节目,节目被删除后,将不再接收
 *输  入：dir,节目路径
 *输  出：
 *返回值：0,已恢复接收; -1,未找到节目; 其它,未知失败
 ***************************************************************************/
int push_dir_remove(const char *dir);


/****************************************************************************
 *函数名：push_dir_get_single
 *功  能：得到指定的注册的节目的已接收字节大小
 *输  入：dir,节目的路径
 *输  出：
 *返回值：long long,指定节目的已接收字节大小
 ***************************************************************************/
long long push_dir_get_single(const char *dir);


/****************************************************************************
 *函数名：push_dir_get_all
 *功  能：得到所有节目的已接收字节大小
 *输  入：dirs,用户传入,用于存储节目路径;
 *        bytes,用于存储节目已接收字节数;
 *        size,指示数组dirs和bytes的大小.
 *输  出：dirs,节目的路径; bytes,节目已接收字节大小
 *返回值：实际节目数
 ***************************************************************************/
int push_dir_get_all(char *dirs[], long long *bytes, int size);


#ifdef __cplusplus
}  /* End of the 'extern "C"' block */
#endif

#endif /* PUSH_H_ */
