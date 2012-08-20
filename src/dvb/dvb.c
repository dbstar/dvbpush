
#include <am_debug.h>
#include <linux/limits.h>
#include <am_dmx.h>
#include "am_dmx_internal.h"
//#include "am_aout_internal.h"
//#include "am_av_internal.h"
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <semaphore.h>

#include "dvbnet.h"
#include "common.h"
#include "mid_push.h"
#include "multicast.h"
#include "porting.h"
#include "dvb.h"

#ifdef ANDROID
#include <sys/socket.h>
#endif
#include <arpa/inet.h>


#define DMX_DEV_NO    (0)
//#define AV_DEV_NO     (0)
//#define AOUT_DEV_NO   (0)
#define DMX_DEV_COUNT      (3)
//#define AV_DEV_COUNT      (1)

#define STREAM_TS_FILE      "/dev/amstream_mpts"

#define DMX0_BUFF_SIZE        (32*1024*2)
#define	DMX_WRITE_POLL_TIMEOUT	(0)
#define DMX_READ_POLL_TIMEOUT   (200)

static int inject_running;

extern const AM_DMX_Driver_t linux_dvb_dmx_drv;
extern AM_ErrorCode_t dvb_open(AM_DMX_Device_t *dev, const AM_DMX_OpenPara_t *para);
extern AM_ErrorCode_t dvb_close(AM_DMX_Device_t *dev);
extern AM_ErrorCode_t dvb_alloc_filter(AM_DMX_Device_t *dev, AM_DMX_Filter_t *filter);
extern AM_ErrorCode_t dvb_free_filter(AM_DMX_Device_t *dev, AM_DMX_Filter_t *filter);
extern AM_ErrorCode_t dvb_set_sec_filter(AM_DMX_Device_t *dev, AM_DMX_Filter_t *filter, const struct dmx_sct_filter_params *params);
extern AM_ErrorCode_t dvb_set_pes_filter(AM_DMX_Device_t *dev, AM_DMX_Filter_t *filter, const struct dmx_pes_filter_params *params);
extern AM_ErrorCode_t dvb_enable_filter(AM_DMX_Device_t *dev, AM_DMX_Filter_t *filter, AM_Bool_t enable);
extern AM_ErrorCode_t dvb_set_buf_size(AM_DMX_Device_t *dev, AM_DMX_Filter_t *filter, int size);
extern AM_ErrorCode_t dvb_poll(AM_DMX_Device_t *dev, AM_DMX_FilterMask_t *mask, int timeout);
extern AM_ErrorCode_t dvb_read(AM_DMX_Device_t *dev, AM_DMX_Filter_t *filter, uint8_t *buf, int *size);
extern AM_ErrorCode_t dvb_set_source(AM_DMX_Device_t *dev, AM_DMX_Source_t src);
//extern void usleep(int mseconds); 
extern AM_ErrorCode_t AM_FileEcho(const char *name, const char *cmd);
//extern const AM_AV_Driver_t aml_av_drv;

#if 0
static AM_AOUT_Device_t aout_devices[] =
{
	{
		.lock  = PTHREAD_MUTEX_INITIALIZER
	}
};

static AM_AV_Device_t av_devices[AV_DEV_COUNT] =
{
	/*{
		.drv = &aml_av_drv
	}*/
};
#endif

static AM_DMX_Device_t dmx_devices[DMX_DEV_COUNT] =
{
	{
		.drv = &linux_dvb_dmx_drv,
		.src = AM_DMX_SRC_HIU
	},
	{
		.drv = &linux_dvb_dmx_drv,
		.src = AM_DMX_SRC_TS0
	},
	{
		.drv = &linux_dvb_dmx_drv,
		.src = AM_DMX_SRC_TS0
	}
};
static sem_t s_sem_dmx;

/*音频控制（通过解码器）操作*/
/*static AM_ErrorCode_t adec_cmd(const char *cmd)
{
AM_ErrorCode_t ret;
char buf[32];
int fd;

ret = AM_LocalConnect("/tmp/amadec_socket", &fd);
if(ret!=AM_SUCCESS)
return ret;

ret = AM_LocalSendCmd(fd, cmd);

if(ret==AM_SUCCESS)
{
ret = AM_LocalGetResp(fd, buf, sizeof(buf));
}

close(fd);

return ret;
}*/

static void dump_bytes(int dev_no, int fid, const uint8_t *data, int len, void *user_data)
{
	//	int i;
	send_mpe_sec_to_push_fifo((unsigned char *)data,len);	
	//	DEBUG("section:\n");
	/*		for(i=0;i<len;i++)
	{
	DEBUG("%02x ", data[i]);
	if(((i+1)%16)==0) DEBUG("\n");
	}
	
	if((i%16)!=0) DEBUG("\n);*/
	//DEBUG("**\n");
}

//#define READ_FILE
static int s_KBps_time_pin = 0;
static void* data_source_thread()
{
	static unsigned char buf[DMX0_BUFF_SIZE];//,buf1[DMX0_BUFF_SIZE],buf2[DMX0_BUFF_SIZE];
	int len, left=0, send, ret, total=0;
	int fd;
#ifdef READ_FILE
	FILE *fd1;//,*fd2;
#endif
	char data_source[64];
	memset(data_source, 0, sizeof(data_source));
	if(-1==data_source_get(data_source, sizeof(data_source)-1)){
		DEBUG("has no data source to process, exit from %s()\n", __FUNCTION__);
		return NULL;
	}
	if(0==strncmp(data_source, "file://", strlen("file://")) || 0==strncmp(data_source, "igmp://", strlen("igmp://"))){
		;
	}
	else{
		DEBUG("data source is invalid: %s, exit from %s()\n", data_source, __FUNCTION__);
		return NULL;
	}
	
#ifdef READ_FILE
	if(0==strncmp(data_source, "file://", strlen("file://"))){
		fd1 = fopen(data_source+strlen("file://"), "r");
		if (!fd1)
		{
			DEBUG("open file %s failed and return from fun %s()\n", data_source, __FUNCTION__);
			return NULL;
		}
	}
	else
#endif
	{
		DEBUG("here do not join multicast\n");
		return;
	}
	
	fd = open(STREAM_TS_FILE, O_RDWR);
	if(fd==-1)
	{
		ERROROUT( "cannot open device [%s]\n", STREAM_TS_FILE);
		return NULL;
	}
	else
		DEBUG("open %s with fd: %d\n", STREAM_TS_FILE, fd);
	
	DEBUG("inject thread start\n");
	if(0==s_KBps_time_pin)
		s_KBps_time_pin = time(NULL);
		
	while(inject_running)
	{
		len = 188-left;//188*8+2048+1024 -left;//1024+2048-left;//DMX0_BUFF_SIZE-left;
//		DEBUG("lllllen = [%d]\n",len);
#if 0
		ret = read(sock, buf+left, len);
#else
		if (len <= 0){
			//DEBUG("no need to read, left=%d, 2*188-left=%d\n", left, len);
			ms_sleep(10);
			continue;
		}
		
#ifdef READ_FILE
		if(0==strncmp(data_source, "file://", strlen("file://")))
			ret = fread(buf+left,1,len,fd1);
		else
#endif
			ret = multi_buf_read(buf+left, len);
		
		total += ret;
		
		static int s_total_print_watermark = 0;
		int footprint = 25;
		if((total>>footprint)>s_total_print_watermark)
		{
			s_total_print_watermark = total>>footprint;
			DEBUG("+%d \t= %dMBs\t|%dKBs\t|%dBs\n", ret, total>>20, total>>10, total);
		}
#endif
		if(ret>0)
		{
			//				DEBUG( "recv %d bytes\n", ret);
			left += ret;
		}
		else	// if(ret<=0)
		{
			//DEBUG("read failed total = [%dMBs,%dKBs,%d]\n",total>>20, total>>10, total);
#ifdef READ_FILE
			if(0==strncmp(data_source, "file://", strlen("file://"))){
				fclose(fd1);
				break;
			}
#endif
		}
		
		if(left>0)
		{
			send = left;
//			int timeout = DMX_WRITE_POLL_TIMEOUT;	//300;
//			//AM_AV_InjectData(AV_DEV_NO, AM_AV_INJECT_MULTIPLEX, buf, &send, -1);
//			if(timeout>=0)
//			{
//				struct pollfd pfd;
//				
//				pfd.fd = fd;
//				pfd.events = POLLOUT;
//				
//				ret = poll(&pfd, 1, timeout);
//				if(ret!=1)
//				{
//					DEBUG("$$$$$$$$$$$$$$$$$$$$$$$$$$$$err\n");
//					//  return AM_AV_ERR_TIMEOUT;
//				}
//			}
			ret = write(fd, buf, send);
//			DEBUG("write to %d, len=%d/%d\n", fd, ret, send);
			if (ret > 0)
			{
				left -= ret;
				if(left>0)
				{
					DEBUG("****************************************\n");
					memmove(buf, buf+ret, left);
				}
				else
					left = 0;	
			}
			else	//if (ret <= 0) 
			{
				if((ret==-1) && (errno!=EAGAIN))
				{
					DEBUG( "inject data failed errno:%d msg:%s\n", errno, strerror(errno));
					break;
				}
				ERROROUT("write len=%d to dev failed, ret=%d\n",send,ret);
				ret = 0;
			}
			//ms_sleep(1);
		}
		else
			ms_sleep(1);
	}
	
	DEBUG( "inject thread end\n");
	close(fd);
	return NULL;
}

static void* dmx_thread(void *arg)
{
	AM_DMX_Device_t *dev = (AM_DMX_Device_t*)arg;
	static unsigned char sec_buf[4096];
	unsigned char *sec;
	int sec_len;
	AM_DMX_FilterMask_t mask;
	AM_ErrorCode_t ret;
	
	DEBUG("start dmx data thread....\n");	
	while(dev->enable_thread)
	{
		//DEBUG("---dmx data\n");
		AM_DMX_FILTER_MASK_CLEAR(&mask);
		int id;
		
		ret = dvb_poll(dev, &mask, DMX_READ_POLL_TIMEOUT);
		if(ret==AM_SUCCESS)
		{
			if(AM_DMX_FILTER_MASK_ISEMPTY(&mask))
			continue;
			
#if 0//defined(DMX_WAIT_CB) || defined(DMX_SYNC)
			pthread_mutex_lock(&dev->lock);
			dev->flags |= DMX_FL_RUN_CB;
			pthread_mutex_unlock(&dev->lock);
#endif
			//DEBUG("-dmx2\n");		
			for(id=0; id<DMX_FILTER_COUNT; id++)
			{
				AM_DMX_Filter_t *filter=&dev->filters[id];
				AM_DMX_DataCb cb;
				void *data;
				
				if(!AM_DMX_FILTER_MASK_ISSET(&mask, id))
					continue;
				if(!filter->enable || !filter->used)
					continue;
				
				sec_len = sizeof(sec_buf);
				
#ifndef DMX_WAIT_CB
				pthread_mutex_lock(&dev->lock);
#endif
				if(!filter->enable || !filter->used)
				{
					ret = AM_FAILURE;
				}
				else
				{
					cb   = filter->cb;
					data = filter->user_data;
					ret  = dev->drv->read(dev, filter, sec_buf, &sec_len);
					//DEBUG("--read [%d]\n",sec_len);
				}
#ifndef DMX_WAIT_CB
				pthread_mutex_unlock(&dev->lock);
#endif
				if(ret==AM_DMX_ERR_TIMEOUT)
				{
					sec = NULL;
					sec_len = 0;
					continue;
				}
				else if(ret!=AM_SUCCESS)
				{
					continue;
				}
				else
				{
					sec = sec_buf;
				}
						
				if(cb)
				{
					cb(dev->dev_no, id, sec, sec_len, data);
				}
			}
#if 0// defined(DMX_WAIT_CB) || defined(DMX_SYNC)
			pthread_mutex_lock(&dev->lock);
			dev->flags &= ~DMX_FL_RUN_CB;
			pthread_mutex_unlock(&dev->lock);
			pthread_cond_broadcast(&dev->cond);
#endif
		}
		else
		{
			usleep(10000);
		}
	}
	
	return NULL;
}

int dvb_init(void)
{
	return 0;
	
	
	
	
	
	AM_DMX_OpenPara_t para;
	AM_DMX_Device_t *dev;
	AM_ErrorCode_t ret = AM_SUCCESS;
	//struct dmx_sct_filter_params param;
	int fid;
	pthread_t th;
	
	if(-1==sem_init(&s_sem_dmx, 0, 1)){
		DEBUG("s_sem_dmx init failed\n");
		return -1;
	}
	
	dev = &dmx_devices[DMX_DEV_NO];
	
	if(dev->openned)
	{
		DEBUG("dmx device had been opened....\n");
	}
	dev->dev_no = DMX_DEV_NO;
	memset(&para, 0, sizeof(para));
	ret = dvb_open(dev,&para);
#if 1 //###########	
	if(ret==AM_SUCCESS)
	{
		DEBUG("dvb open successful...\n");
		pthread_mutex_init(&dev->lock, NULL);
		//pthread_cond_init(&dev->cond, NULL);
		dev->enable_thread = AM_TRUE;
		dev->flags = 0;
		
		if(pthread_create(&dev->thread, NULL, dmx_thread, dev))
		{
			pthread_mutex_destroy(&dev->lock);
			//pthread_cond_destroy(&dev->cond);
			goto finish;
		}
		DEBUG("dvb creat pthread successful..\n");
	}
#endif	
	if(ret==AM_SUCCESS)
	{
		dev->openned = AM_TRUE;
	}
	else
	{
		DEBUG("dmx device open failed...\n");
		goto finish;
	}

	//AM_DMX_SetSource(DMX_DEV_NO, AM_DMX_SRC_HIU);
	ret = dvb_set_source(dev,AM_DMX_SRC_HIU);
	if(ret!=AM_SUCCESS)
	{
		DEBUG("dmx device set source failed...\n");
		goto finish;
	}
	DEBUG("dvb dmx set source successful...\n");
	AM_FileEcho("/sys/class/stb/source", "hiu");
	
#if 0	
	#if 1  //############
		DEBUG("dvb allocate a filter...\n");
		//AM_DMX_AllocateFilter(psec->dev_no, &psec->hfilter);
		for(fid=0; fid<DMX_FILTER_COUNT; fid++)
		{
			if(!dev->filters[fid].used)
			break;
		}
		if(fid>=DMX_FILTER_COUNT)
		{
			DEBUG("no free section filter\n");
			ret = AM_DMX_ERR_NO_FREE_FILTER;
		}
		if(ret==AM_SUCCESS)
		{
			DEBUG("dvb filter id = [%d]\n",fid);
			dev->filters[fid].id   =  fid;
			ret = dvb_alloc_filter(dev,&dev->filters[fid]);
		}
		if(ret==AM_SUCCESS)
		{
			dev->filters[fid].used = AM_TRUE;
			//*fhandle = fid;	
			DEBUG( "allocate filter %d\n", fid);
		}
		DEBUG("dvb set call back for a filter...\n");	
		//AM_DMX_SetCallback(DMX_DEV_NO, fid, dump_bytes, NULL)
		{
			AM_DMX_Filter_t *filter;
			
			filter = &dev->filters[fid];
			filter->cb = (AM_DMX_DataCb)dump_bytes;
			filter->user_data = NULL;
		}
		//AM_DMX_SetBufferSize(psec->dev_no, psec->hfilter, 32*1024);
		ret = dvb_set_buf_size(dev,&dev->filters[fid],40*DMX0_BUFF_SIZE);
		DEBUG("dvb set buf size = [%d]\n",DMX0_BUFF_SIZE);
		//set section filter
		memset(&param, 0, sizeof(param));
		param.pid = root_channel_get();
		param.filter.filter[0] = 0x3e;
		param.filter.mask[0] = 0xff;
		//param.filter.filter[0] = psec->table_id;
		//param.filter.mask[0] = 0xff;
		param.filter.filter[4] = 0;//psec->cur_sec;
		param.filter.mask[4] = 0xff;
		param.flags = DMX_CHECK_CRC;
		DEBUG("dvb set sec filter...\n");
		//AM_DMX_SetSecFilter(psec->dev_no, psec->hfilter, &param);
		ret = dvb_set_sec_filter(dev,&dev->filters[fid],&param);
		DEBUG("set dvb filter, pid=%d\n", param.pid);
		
		//AM_DMX_StartFilter(psec->dev_no, psec->hfilter);
		ret = dvb_enable_filter(dev, &dev->filters[fid], AM_TRUE);
		DEBUG("dvb star filter...\n");	
		dev->filters[fid].enable = AM_TRUE;	
		/*vfd = open(STREAM_TS_FILE, O_RDWR);
		if(vfd==-1)
		{
		DEBUG( "cannot open device [%s]", STREAM_TS_FILE);
		goto finish;
		}*/
	#endif
#else
	fid = TC_SetFilter(root_channel_get());
	if(-1==fid){
		DEBUG("dvb set filter with pid %d failed\n", root_channel_get());
		return -1;
	}
	DEBUG("set demux filter in xmlparser directly, pid=%d, fid=%d\n", root_channel_get(), fid);
	
	int l_data_pid = 102;	//prog_data_pid_get();
//	if(l_data_pid>100)
	{
		int fid2 = TC_SetFilter(l_data_pid);
		if(-1==fid2){
			DEBUG("dvb set filter with pid %d failed\n", l_data_pid);
			return -1;
		}
		DEBUG("set demux filter in xmlparser directly, pid=%d, fid=%d\n", l_data_pid, fid2);
	}
//	else
//		DEBUG("ignore this data pid %d\n", l_data_pid);

#endif

	inject_running = 1;
	pthread_create(&th, NULL, data_source_thread, NULL);
	DEBUG("dvb cread inject entry thread\n");


finish:

#if 0
	DEBUG("dvb exit...\n");
	TC_ReleaseFilter(fid);
	dev->enable_thread = AM_FALSE;
	pthread_join(dev->thread, NULL);
	inject_running = 0;
	pthread_join(th, NULL);
	
	//AM_AV_StopInject(AV_DEV_NO);
	//close(vfd);
	finish:
	//AM_DMX_Close(DMX_DEV_NO);
	dvb_close(dev);
	//close(sock);
#endif
	return 0;
}

/* 
设置数据过滤器 
*/
static int TC_SetFilter_son ( unsigned short wPid, 
    const unsigned char *pFilter, const unsigned char *pMask, char pLen, void *phandler, void *userdata ) 
{
    AM_DMX_Device_t *dev;
    struct dmx_sct_filter_params param;
    //AM_DMX_Filter_t *filter;
    int fid,i;
	
    dev = &dmx_devices[DMX_DEV_NO];
      
    for(fid=0; fid<DMX_FILTER_COUNT; fid++)
    {
        if(!dev->filters[fid].used)
            break;
    }
    if(fid < DMX_FILTER_COUNT)
    {
        dev->filters[fid].id   =  fid;
        if (dvb_alloc_filter(dev,&dev->filters[fid]) == AM_SUCCESS)
        {
            dev->filters[fid].used = AM_TRUE;   
            //printf("dvb set call back for a filter...\n");
            //AM_DMX_SetCallback(DMX_DEV_NO, fid, dump_bytes, NULL)
            //filter = &dev->filters[fid];
            if (phandler)
                dev->filters[fid].cb = (AM_DMX_DataCb)phandler;
            else
            	dev->filters[fid].cb = NULL;
            	
            if (userdata)
            	dev->filters[fid].user_data = userdata;
            else
                dev->filters[fid].user_data = NULL;
            //AM_DMX_SetBufferSize(psec->dev_no, psec->hfilter, 32*1024);
            dvb_set_buf_size(dev,&dev->filters[fid],40*DMX0_BUFF_SIZE);

            //set section filter
            memset(&param, 0, sizeof(param));
            param.pid = wPid;
            for (i=0; i<pLen; i++)
            {
                param.filter.filter[i] = pFilter[i];
                param.filter.mask[i] = pMask[i];
            }
            param.flags = DMX_CHECK_CRC;
 
            //AM_DMX_SetSecFilter(psec->dev_no, psec->hfilter, &param);
            dvb_set_sec_filter(dev,&dev->filters[fid],&param);

            //AM_DMX_StartFilter(psec->dev_no, psec->hfilter);
            dvb_enable_filter(dev, &dev->filters[fid], AM_TRUE);
            dev->filters[fid].enable = AM_TRUE;
            return fid;
        }
    }
    return -1;
}

int TC_SetFilter(int pid)
{
	unsigned char tcfilter[8],tcmask[8],tclen;
 
	tcfilter[0]=0x3e;
	tcmask[0]=0xff;
	tclen = 1;
	void (*dump_bytes_cb)(int dev_no, int fid, const uint8_t *data, int len, void *user_data) = dump_bytes;
	
	sem_wait(&s_sem_dmx);
	int ret = TC_SetFilter_son((unsigned short)pid,tcfilter,tcmask,tclen,dump_bytes_cb,NULL);
	sem_post(&s_sem_dmx);
	
	DEBUG("set demux filter with pid=%d, fid=%d\n", pid, ret);
	return ret;
}

/*
 释放私有数据过滤器，参数为滤波器的id号。
  */
void TC_ReleaseFilter( int fid )
{
    AM_DMX_Device_t *dev;
	
    if ((fid >= DMX_FILTER_COUNT) || (fid < 0))
    	return;
    
	sem_wait(&s_sem_dmx);
	
    dev = &dmx_devices[DMX_DEV_NO];
    dvb_enable_filter(dev, &dev->filters[fid], AM_FALSE);
    dev->filters[fid].enable = AM_FALSE;
    dvb_free_filter(dev,&dev->filters[fid]);
    dev->filters[fid].used=AM_FALSE;
    
	sem_post(&s_sem_dmx);
	
    DEBUG("release demux filter, fid=%d\n", fid);
	return;
}

