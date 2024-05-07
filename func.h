#ifndef FUNC_H
#define FUNC_H

#include <stdint.h>

void set_parameter(int argc, char *argv[]); //设置程序命令参数

int bind_port(); //绑定UDP端口
int load_config(); //加载配置文件

void add_host_info(char domain[], uint8_t IPAddr[]); //添加HOST信息

#endif