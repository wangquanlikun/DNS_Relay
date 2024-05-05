#ifndef DATA_H
#define DATA_H

#define TRUE 1
#define FALSE 0
#define SUCCESS 1
#define FAIL 0

#define VERSION "0.1.0"

#define NO_DEBUG 0
#define DEBUG_MODE_1 1
#define DEBUG_MODE_2 2
extern int debug_mode;

#define DEFAULT_ADDRESS "202.106.0.20"
extern char server_ip[16];

#define DEFAULT_PATH "./dnsrelay.txt"
extern char config_path[100];

extern const int port;

typedef struct trie_node { 
	uint16_t pre;
	uint16_t val[37];
	uint8_t IP[4];
	uint8_t isEnd;
} trie;
trie list_trie[65535]; //字典树
extern int list_size;
int map[256]; //字符映射表

#endif