#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "xmlparser.h"
#include "sqlite.h"
#include "mid_push.h"
#include "porting.h"
#include "multicast.h"
#include "timeprint.h"

int main(int argc, char *argv[])
{
	DEBUG("dbstar data process start...\n");
	compile_timeprint();
	
	if(0){
		DEBUG("argc: %d, argv[0]: %s\n", argc, argv[0]);
	}
	
	if(-1==setting_init()){
		DEBUG("setting init failed\n");
		return -1;
	}
	
	if(-1==sqlite_init()){
		DEBUG("sqlite init failed\n");
		return -1;
	}
	
	if(-1==xmlparser_init()){
		DEBUG("xmlparser init failed\n");
		return -1;
	}

	// 可以开始解析指定的xml文件
	//parseDoc(xxxxx.xml);
	
	if(-1==mid_push_init(PUSH_CONF)){
		DEBUG("push model init with \"%s\" failed\n", PUSH_CONF);
		return -1;
	}
	
	if(-1==softdvb_init()){
		DEBUG("dvb init with failed\n");
		return -1;
	}
	
	if(-1==igmp_init()){
		DEBUG("igmp init failed\n");
		return -1;
	}
	
	int running = 1;
	char buf[256];
	while(running)
	{
		//	if(gets(buf))
		{
			if(!strncmp(buf, "quit", 4))
			{
				running = 0;
			}
		}
		sleep(1000);
	}
	
	return 0;
}

