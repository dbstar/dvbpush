#ifndef __MULTICAST_H__
#define __MULTICAST_H__

int multicast_init(char *tmp_file_name);
int multicast_add(const char *multi_addr);
int multi_buf_read(unsigned char *buf, unsigned int len);
int softdvb_init();
int igmp_init();
int alloc_filter(unsigned short pid);
void free_filter(int fid);

#endif
