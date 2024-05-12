#ifndef DNS_DATA_H
#define DNS_DATA_H

/*
    DNS 报文格式：
    +---------------------+
    |        Header       | 报文头，固定12字节
    +---------------------+
    |       Question      | 向域名服务器的查询请求
    +---------------------+ 
    |        Answer       | 对于查询问题的回复
    +---------------------+
    |      Authority      | 指向授权域名服务器
    +---------------------+
    |      Additional     | 附加信息
    +---------------------+
*/

#include <stdint.h>

struct DNS_HEADER {
    uint16_t ID; // 16位标识符
    uint8_t QR : 1; // 1位，查询/响应标志
    uint8_t OPCODE : 4; // 4位，操作码
    uint8_t AA : 1; // 1位，表示授权回答
    uint8_t TC : 1; // 1位，表示可截断的
    uint8_t RD : 1; // 1位，表示期望递归
    uint8_t RA : 1; // 1位，表示可用递归
    uint8_t Z : 3; // 3位，必须为0
    uint8_t RCODE : 4; // 4位，响应码
    uint16_t QDCOUNT; // 16位，问题数
    uint16_t ANCOUNT; // 16位，回答数
    uint16_t NSCOUNT; // 16位，授权数
    uint16_t ARCOUNT; // 16位，附加数
};

struct DNS_QUESTION {
    char QNAME[300]; // 查询名
    uint16_t QTYPE; // 16位，查询类型
    uint16_t QCLASS; // 16位，查询类
    struct DNS_QUESTION *next; // 下一个查询
};

struct DNS_RR {
    char NAME[300]; // 16位，资源记录名
    uint16_t TYPE; // 16位，资源记录类型
    uint16_t CLASS; // 16位，资源记录类
    uint32_t TTL; // 32位，生存时间
    uint16_t RDLENGTH; // 16位，数据长度
    uint8_t *RDATA; // 变长，资源数据
    struct DNS_RR *next; // 下一个资源记录
};

#define DNS_TYPE_A 1 // IPv4地址
#define DNS_TYPE_NS 2 // 域名服务器
#define DNS_TYPE_CNAME 5 // 规范名称
#define DNS_TYPE_SOA 6 // 开始授权
#define DNS_TYPE_PTR 12 // 指针
#define DNS_TYPE_MX 15 // 邮件交换
#define DNS_TYPE_TXT 16 // 文本
#define DNS_TYPE_AAAA 28 // IPv6地址

#define DNS_CLASS_IN 1 // Internet地址

#define DNS_RCODE_NO_ERROR 0 // 没有错误
#define DNS_RCODE_FORMAT_ERROR 1 // 格式错误
#define DNS_RCODE_SERVER_FAILURE 2 // 服务器错误
#define DNS_RCODE_NAME_ERROR 3 // 名称错误
#define DNS_RCODE_NOT_IMPLEMENTED 4 // 未实现
#define DNS_RCODE_REFUSED 5 // 拒绝

struct dns_data {
    struct DNS_HEADER header;
    struct DNS_QUESTION *question;
    struct DNS_RR *answer;
    struct DNS_RR *authority;
    struct DNS_RR *additional;
};
typedef struct dns_data DNS_DATA;

#endif