#ifndef DATA_H
#define DATA_H

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

#endif