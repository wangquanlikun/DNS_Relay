#ifndef FUNC_H
#define FUNC_H

void set_parameter(int argc, char *argv[]); //设置程序命令参数

int bind_port(); //绑定UDP端口
int load_config(); //加载配置文件

#endif