#include "header.h"
#include "dns_data.h"

int addr_len = sizeof(struct sockaddr_in);

void receive_client() { //接收客户端DNS，查询，回复或上交远程DNS服务器处理
    char recv_buffer[BUFFER_SIZE];
    char ansTo_buffer[BUFFER_SIZE];
    DNS_DATA dns_msg;
    uint8_t ip_addr[4] = {0};
    int msg_size = -1;
    int is_found = 0;

    msg_size = recvfrom(client_socket, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr*)&client_addr, &addr_len);

    if (msg_size >= 0) {  //接收到请求响应

    }
}

void receive_server() {

}