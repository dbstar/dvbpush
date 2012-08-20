#ifndef __MID_PUSH_H__
#define __MID_PUSH_H__

int send_mpe_sec_to_push_fifo(unsigned char *pkt, int pkt_len);

int mid_push_init(char *push_conf);
int mid_push_regist(char *id, char *content_uri, long long content_len);
int mid_push_unregist(char *content_uri);

int push_data_root_dir_get(char *buf, unsigned int size);

#endif
