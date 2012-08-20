﻿#ifndef __PORTING_H__
#define __PORTING_H__

char *setting_item_value(char *buf, unsigned int len);
int setting_init(void);
int service_id_get(char *id, unsigned int len);
int root_channel_get(void);
int root_push_file_get(char *filename, unsigned int len);
int root_push_file_size_get(void);
int data_source_get(char *data_source, unsigned int len);
int database_uri_get(char *database_uri, unsigned int size);

int prog_data_pid_get(void);

int ifconfig_get(char *interface_name, char *ip, char *status, char *mac);

#endif
