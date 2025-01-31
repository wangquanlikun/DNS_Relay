#ifndef FUNC_H
#define FUNC_H

#include <stdint.h>
#include <winsock2.h>
#include "dns_data.h"
#include "data.h"

void set_parameter(int argc, char *argv[]); //设置程序命令参数

int bind_port(); //绑定UDP端口
int load_config(); //加载配置文件

void add_host_info(char domain[], uint8_t IPAddr[]); //添加HOST信息

void init_data(); //初始化数据
void debug_print(char output_info[]); //调试输出
void debug_print_DNS(const DNS_DATA* dns_msg); //调试输出DNS报文

void run_server(); 
void receive_client();
void receive_server();
void Thread_receive_client();
void Thread_receive_server();
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

void get_dns_msg(char recv_buffer[], DNS_DATA* dns_msg); //解析DNS报文
void free_dns_struct(DNS_DATA* dns_data); //释放DNS_DATA结构体
void set_dns_ans(DNS_DATA* dns_msg, uint8_t ip_addr[], char name[], uint16_t QTYPE); //设置DNS_ANSWER
void set_nodomain_ans(DNS_DATA* dns_msg); //设置无域名(0.0.0.0)回答
int set_dns_msg(char ansTo_buffer[], DNS_DATA* dns_msg); //设置DNS报文

int find_cache(char domain[], uint8_t ip_addr[], uint16_t QTYPE); //查找缓存
void update_cache(uint8_t ip_addr[], char domain[], uint16_t QTYPE); //更新缓存
int find_trie(char domain[], uint8_t ip_addr[], uint16_t QTYPE); //查找字典树
void write_back_trie(char domain[], uint8_t ip_addr[], uint16_t QTYPE); //写回字典树
void write_back_file(char domain[], uint8_t ip_addr[], uint16_t QTYPE); //写回文件

uint16_t set_ID(uint16_t client_ID, struct sockaddr_in client_address); //消息ID转换

void initThreadPool();
unsigned __stdcall workerThreadProc(void* param);
void submitToThreadPool(ThreadParams pParams);
DWORD WINAPI ProcessDNSThread(LPVOID lpParam);
void ProcessServer(ThreadParams* pParams);
void ProcessClient(ThreadParams* pParams);
#endif