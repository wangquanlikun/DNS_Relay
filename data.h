#ifndef DATA_H
#define DATA_H

#include <stdint.h>
#include <WinSock2.h>
#include <ws2tcpip.h>

#define TRUE 1
#define FALSE 0
#define SUCCESS 1
#define FAIL 0

#define VERSION "0.1.0"

#define NO_DEBUG 0
#define DEBUG_MODE_1 1
#define DEBUG_MODE_2 2
extern int debug_mode;

#define DEFAULT_MODE 1
#define POLL_MODE 2
extern int mode;

#define DEFAULT_ADDRESS "10.3.9.4"
extern char server_ip[16];

#define DEFAULT_PATH "./dnsrelay.txt"
extern char config_path[100];

#define BUFFER_SIZE 1500

extern const int port;

typedef struct trie_node { 
	uint16_t pre;
	uint16_t val[37];
	uint8_t IP[4];
	uint8_t isEnd;
} trie;
trie list_trie[65535]; //字典树
extern int list_size;
extern int map[256]; //字符映射表

SOCKET server_socket;
SOCKET client_socket;
SOCKADDR_IN client_addr;
SOCKADDR_IN server_addr;

extern int addr_len;

typedef struct lru_node {
	uint8_t IP[4];
	char domain[300];
	struct lru_node* next;
} LRU_NODE; // LRU缓存
struct lru_node* lru_head;
extern int cache_size;
#define MAX_CACHE_SIZE 100

typedef struct {
	uint16_t client_ID;
	int expire_time;
	struct sockaddr_in client_addr;
} ID_conversion;
#define MAX_ID_LIST 255
ID_conversion ID_list[MAX_ID_LIST]; // ID转换表

#endif