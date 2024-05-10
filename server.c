#include "header.h"

int debug_mode = NO_DEBUG;
char server_ip[16] = DEFAULT_ADDRESS;
char config_path[100] = DEFAULT_PATH;
const int port = 53;

extern trie list_trie[65535];
int list_size = 0;
int char_map[256];

static void print_info() {
    const char date[] = __DATE__;
    const char time[] = __TIME__;

    printf("SourceCode at https://github.com/wangquanlikun/DNS_Relay. Fork and Star\n\n");
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
    #ifdef _WIN32

    WORD wVersion = MAKEWORD(2, 2);
    WSADATA wsaData;
    if(WSAStartup(wVersion, &wsaData) != 0) {
        return FAIL;
    }

    client_socket = socket(AF_INET, SOCK_DGRAM, 0);
    server_socket = socket(AF_INET, SOCK_DGRAM, 0);

    memset(&client_addr, 0, sizeof(client_addr));
    memset(&server_addr, 0, sizeof(server_addr));

    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = INADDR_ANY;
    client_addr.sin_port = htons(port);

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(server_ip);
    server_addr.sin_port = htons(port);

    const int reuse = 1;
    if(setsockopt(client_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) == SOCKET_ERROR) {
        return FAIL;
    }

    if(bind(client_socket, (SOCKADDR*)&client_addr, sizeof(client_addr)) == SOCKET_ERROR) {
        return FAIL;
    }
    printf("OK.\n");
    return SUCCESS;

    #else

    #endif
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
    char addr[16];
    char domain[300];

    FILE* config_file_ptr = fopen(config_path, "r");
    if (!config_file_ptr) {
        return FAIL;
    }
    else {
        printf("OK.\n");
        int num = 0;
        creat_char_to_int_Map();

        fscanf(config_file_ptr, "%s", addr);
        fscanf(config_file_ptr, "%s", domain);

        while(!feof(config_file_ptr)) {
            memset(IPAddr, 0, sizeof(IPAddr));
            int i, j;
            for (i = 0, j = 0; i < 4 && j < 16; j++) {
                if(addr[j] == '.') {
                    i++;
                }
                else if (addr[j] == '\0') {
                    break;
                }
                else {
                    IPAddr[i] = (uint8_t)(IPAddr[i] * 10 + (addr[j] - '0'));
                }
            }

            add_host_info(domain, IPAddr);
            num++;

            if(debug_mode == DEBUG_MODE_2) {
                printf("\t%d: %hhu.%hhu.%hhu.%hhu\t %s\n", num, IPAddr[0], IPAddr[1], IPAddr[2], IPAddr[3], domain);
            }

            fscanf(config_file_ptr, "%s", addr);
            fscanf(config_file_ptr, "%s", domain);
        }

        printf("Load %d names.\n", num);
        fclose(config_file_ptr);
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

void init_data() {
    // 初始化ID转换表
    for (int i = 0; i < MAX_ID_LIST; i++)
    {
        ID_list[i].client_ID = 0;
        ID_list[i].expire_time = 0;
        memset(&(ID_list[i].client_addr), 0, sizeof(struct sockaddr_in));
    }

    // 初始化LRU缓存 -- 链表头指针
    lru_head = malloc(sizeof(struct lru_node)); // 带头结点
    lru_head->next = NULL;
}

void run_server() {
    #ifdef _WIN32

    u_long nonBlockingMode = 1;
    int ser_result = ioctlsocket(server_socket, FIONBIO, &nonBlockingMode);
    int cli_result = ioctlsocket(client_socket, FIONBIO, &nonBlockingMode);

    if(ser_result == SOCKET_ERROR || cli_result == SOCKET_ERROR) {
        printf("Set non-blocking mode failed.\n");
        closesocket(server_socket);
        closesocket(client_socket);
        WSACleanup();
        exit(1);
    }

    #else

    #endif

    // success
    while (1) {
        receive_client();
        receive_server();
    }
}

void debug_print(char output_info[]) {
    if(debug_mode == NO_DEBUG)
        return;
    else {
        int i;
        char c = output_info[0];
        int str_len = strlen(output_info);
        for (i = 0; i < str_len; i++) {
            c = output_info[i];
            if(c == '#') {
                if (debug_mode == DEBUG_MODE_1)
                    break;
                else if (debug_mode == DEBUG_MODE_2 && i != 0)
                    putchar('\n');
            }
            else
                putchar(c);
        }
        if((debug_mode == DEBUG_MODE_1 && i != 0)|| (debug_mode == DEBUG_MODE_2 && c != '#'))
            putchar('\n');
        return;
    }
}