

#include <am_debug.h>
#include <am_smc.h>
#include <string.h>
#include <unistd.h>
//#include <am_time.h>
#include <am_mem.h>
#include "am_smc_internal.h"
//#include "am_adp_internal.h"
#include <limits.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <linux/amsmc.h>

int smc_test(void)
{
        AM_SMC_OpenPara_t para;
	uint8_t atr[AM_SMC_MAX_ATR_LEN];
	int i, len, ds;
	AM_SMC_CardStatus_t status;
	uint8_t sbuf[5]={0x80, 0x44, 0x00, 0x00, 0x08};
//	uint8_t rbuf[256];
//	int rlen = sizeof(rbuf);
        char name[PATH_MAX];
        char data[1024];
        int fd,ret;

	
	memset(&para, 0, sizeof(para));
	//para.enable_thread = !sync;
	//AM_TRY(AM_SMC_Open(SMC_DEV_NO, &para));
	
	snprintf(name, sizeof(name), "/dev/smc0");
	fd = open(name, O_RDWR);
        if (fd < 0) printf("ooooooooopen smc0 error\n");

        printf("please insert a card\n");
	do {
		//AM_TRY(AM_SMC_GetCardStatus(SMC_DEV_NO, &status));
                if(ioctl(fd, AMSMC_IOC_GET_STATUS, &ds))
	        {
		    printf("get card status failed\n");
		    return -1;
                }
	
	        status = ds ? AM_SMC_CARD_IN : AM_SMC_CARD_OUT;
		usleep(100000);
	} while(status==AM_SMC_CARD_OUT);
	
	printf("card in\n");

        len = sizeof(atr);
	//AM_TRY(AM_SMC_Reset(SMC_DEV_NO, atr, &len));
        {
        struct am_smc_atr abuf;
	
	if(ioctl(fd, AMSMC_IOC_RESET, &abuf))
	{
		printf("reset the card failed");
		return -1;
	}
	
	memcpy(atr, abuf.atr, abuf.atr_len);
	len = abuf.atr_len; 

        printf("ATR: ");
	for(i=0; i<len; i++)
	{
		printf("%02x ", atr[i]);
	}
	printf("\n");
        }
        //AM_TRY(AM_SMC_TransferT0(SMC_DEV_NO, sbuf, sizeof(sbuf), rbuf, &rlen));
        {
        struct pollfd pfd;
	
	pfd.fd = fd;
	pfd.events = POLLOUT;
	
	ret = poll(&pfd, 1, 1000);
	if(ret!=1)
	{
                printf("wwwwwwwrite timeout\n");
		return -1;
	}
printf("beggggin wrrite  \n");	
	ret = write(fd, sbuf, 5);
	if(ret<0)
	{
		printf("card write error");
		return -1;
	}
printf("write data == [%d]\n",ret);
//	while(1)
        {
            pfd.fd = fd;
	    pfd.events = POLLIN;
	
	    ret = poll(&pfd, 1, 10000);
	    if(ret!=1)
	    {
                printf("read timeout !!!!!!!!\n");
		return -1;
	    }
printf("begin read  ....\n");
	    ret = read(fd, data, 1);
	    if(ret<0)
	    {
		printf("card read error");
		return -1;
	    }

        }
        }
	printf("send: ");
	for(i=0; i<sizeof(sbuf); i++)
	{
		printf("%02x ", sbuf[i]);
	}
	printf("\n");
	
	printf("recv: ");
//	for(i=0; i<rlen; i++)
	{
		printf("%02x ", data[0]);
	}
	printf("\n");



        close(fd);

        return 0;
}












