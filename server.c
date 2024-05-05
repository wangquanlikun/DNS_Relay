#include "header.h"

int debug_mode = NO_DEBUG;
char server_ip[16] = DEFAULT_ADDRESS;
char config_path[100] = DEFAULT_PATH;
const int port = 53;

extern trie list_trie[65535];
int list_size = 0;
extern int char_map[256];

static void print_info() {
    const char date[] = __DATE__;
    const char time[] = __TIME__;

    printf("SourceCode at https://github.com/wangquanlikun/DNS_Relay. Fork and Star\n");
    printf("DNSRELAY, Version %s, Build: %s %s\n", VERSION, date, time);
    printf("Usage: dnsrelay [-d | -dd] [<dns-server>] [<db-file>]\n\n");
    
    printf("Name server: %s:%d.\n", server_ip, port);
    printf("Debug level %d.\n", debug_mode);

    printf("Bind UDP port %d ...", port);
    if(bind_port() == 0) {
        printf("Failed.\n");
        exit(1);
    }

    printf("Try to load table \"%s\" ...", config_path);
    if(load_config() == 0) {
        printf("Failed.\n");
        exit(1);
    }

    if(debug_mode == DEBUG_MODE_2) {}

}

void set_parameter(int argc, char *argv[]) {
    int parameter_num = argc - 1;
    int parameter_index;

    for (parameter_index = 1; parameter_index <= parameter_num; parameter_index++){

        if(strcmp(argv[parameter_index], "-d") == 0){
            debug_mode = DEBUG_MODE_1;
        }
        else if(strcmp(argv[parameter_index], "-dd") == 0){
            debug_mode = DEBUG_MODE_2;
        }
        
        if(argv[parameter_index][0] >= '0' && argv[parameter_index][0] <= '9'){
            strcpy(server_ip, argv[parameter_index]);
        }

        if(argv[parameter_index][0] == '.' || argv[parameter_index][0] == '/' || (argv[parameter_index][0] >= 'A' && argv[parameter_index][0] <= 'Z')){
            strcpy(config_path, argv[parameter_index]);
        }
    }

    print_info();
}

int bind_port() {
    return 0;
}

static void creat_char_to_int_Map() {
    /****** 构建域名字符到有限数字的映射表
     * 0 - 9 : 0 - 9
     * a - z : 10 - 35
     * A - Z : 36 - 61
     * '-' : 62
     * '.' : 63
     * ******/
    int index, i;
    for (i = 0; i < 128; i++) {
        if((char)i >= '0' && (char)i <= '9') {
            index = i - '0';
        }
        else if((char)i >= 'a' && (char)i <= 'z') {
            index = i - 'a' + 10;
        }
        else if((char)i >= 'A' && (char)i <= 'Z') {
            index = i - 'A' + 36;
        }
        else if((char)i == '-') {
            index = 62;
        }
        else if((char)i == '.') {
            index = 63;
        }
        char_map[i] = index;
    }
}

int load_config() {
    uint8_t IPAddr[4];
    char domain[300];

    FILE* config_file_ptr = fopen(config_path, "r");
    if (!config_file_ptr) {
        return FAIL;
    }
    else {
        printf("OK.\n");
        int num = 0;
        creat_char_to_int_Map();

        while(!feof(config_file_ptr)) {
            fscanf(config_file_ptr, "%hhu.%hhu.%hhu.%hhu", IPAddr, IPAddr + 1, IPAddr + 2, IPAddr + 3);
            fscanf(config_file_ptr, "%s", domain);

            add_host_info(domain, IPAddr);
            num++;

            if(debug_mode == DEBUG_MODE_2) {
                printf("\t%d: %hhu.%hhu.%hhu.%hhu\t %s\n", num, IPAddr[0], IPAddr[1], IPAddr[2], IPAddr[3], domain);
            }
        }

        printf("Load %d names.\n", num);
        return SUCCESS;
    }
}

void add_host_info(char domain[], uint8_t IPAddr[]){
    int domain_len = strlen(domain);
    int index = 0;

    for (int i = 0; i < domain_len; i++) {
        int num = char_map[domain[i]];

        if (list_trie[index].val[num] == 0) {
            list_size++;
            list_trie[index].val[num] = list_size;
        }
        list_trie[list_trie[index].val[num]].pre = index;
        index = list_trie[index].val[num];
    }

    for (int i = 0; i < 4; i++) {
        list_trie[index].IP[i] = IPAddr[i];
    }

    list_trie[index].isEnd = TRUE;
}