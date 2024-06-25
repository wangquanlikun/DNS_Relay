#ifndef FUNC_H
#define FUNC_H

#include <stdint.h>
#include "dns_data.h"

void set_parameter(int argc, char *argv[]); //设置程序命令参数

int bind_port(); //绑定UDP端口
int load_config(); //加载配置文件

void add_host_info(char domain[], uint8_t IPAddr[]); //添加HOST信息

void init_data(); //初始化数据
void debug_print(char output_info[]); //调试输出

void run_server(); 
void receive_client();
void receive_server();

void get_dns_msg(char recv_buffer[], DNS_DATA* dns_msg); //解析DNS报文
void set_dns(DNS_DATA* dns_msg, uint8_t ip_addr[]); //设置DNS_ANSWER
void set_dns_msg(char ansTo_buffer[], DNS_DATA* dns_msg); //设置DNS报文

int find_cache(char domain[], uint8_t ip_addr[]); //查找缓存
void update_cache(uint8_t ip_addr[4], char domain[]); //更新缓存
int find_trie(char domain[], uint8_t ip_addr[]); //查找字典树

uint16_t set_ID(uint16_t client_ID, struct sockaddr_in client_address); //消息ID转换
#endif