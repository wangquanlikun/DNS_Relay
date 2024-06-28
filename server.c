#include "header.h"

int debug_mode = NO_DEBUG;
int mode = DEFAULT_MODE;
char server_ip[16] = DEFAULT_ADDRESS;
char config_path[100] = DEFAULT_PATH;
const int port = 53;

extern trie list_trie[TRIE_LIST_SIZE];
int list_size = 0;
int char_map[256];

#define WM_SOCKET (WM_USER + 1)
HWND hwnd;

HANDLE threadPool[MAX_THREADS];
CRITICAL_SECTION cs;
HANDLE taskQueueMutex;
HANDLE taskQueueSemaphore;
ThreadParams taskQueue[MAX_THREADS]; // 假设任务队列大小与线程池大小相同
int nextTaskIndex;
int taskQueueSize;
CONDITION_VARIABLE conditionVariable;

void initThreadPool() {
    InitializeCriticalSection(&cs);
    taskQueueSemaphore = CreateSemaphore(NULL, 0, MAX_THREADS, NULL);
    InitializeConditionVariable(&conditionVariable);
    for (int i = 0; i < MAX_THREADS; ++i) {
        threadPool[i] = (HANDLE)_beginthreadex(NULL, 0, workerThreadProc, NULL, 0, NULL);
        if (threadPool[i] == NULL) {
            printf("Create thread %d failed\n", i);
        }
    }
}

unsigned __stdcall workerThreadProc(void* param) {
    while (TRUE) {
        WaitForSingleObject(taskQueueSemaphore, INFINITE);
        EnterCriticalSection(&cs);
        int currentIndex = -1;
        if (taskQueueSize > 0) {
            currentIndex = nextTaskIndex;
            nextTaskIndex = (nextTaskIndex + 1) % MAX_THREADS;
            //--taskQueueSize;
        }
        
        if (currentIndex != -1) {
            printf("Thread %d is processing task\n", GetCurrentThreadId());
            ProcessDNSThread(&taskQueue[currentIndex]);
            taskQueueSize--;
        }
        LeaveCriticalSection(&cs);
    }
    return 0;
}

static void print_info() {
    const char date[] = __DATE__;
    const char time[] = __TIME__;

    printf("A Project of BUPT Computer Network Course Design\n\n");
    printf("DNSRELAY, Version %s, Build: %s %s\n", VERSION, date, time);
    printf("Usage: dnsrelay [ -d | -dd ] [ -m1 | -m2 | -m3 | -m4 ] [<dns-server>] [<db-file>]\n\n");
    
    printf("Name server: %s:%d.\n", server_ip, port);
    printf("Debug level %d.\n", debug_mode);
    if(mode == DEFAULT_MODE) {
        printf("Running on non-blocking mode.\n");
    }
    else if(mode == POLL_MODE) {
        printf("Running on poll mode.\n");
    }
    else if(mode == ASYNC_MODE) {
        printf("Running on async mode.\n");
    }
    else if(mode == MUTI_THREAD_MODE) {
        printf("Running on multi-thread mode.\n");
    }

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

        if(strcmp(argv[parameter_index], "-m1") == 0){
            mode = DEFAULT_MODE;
        }
        else if(strcmp(argv[parameter_index], "-m2") == 0){
            mode = POLL_MODE;
        }
        else if(strcmp(argv[parameter_index], "-m3") == 0){
            mode = ASYNC_MODE;
        }
        else if(strcmp(argv[parameter_index], "-m4") == 0){
            mode = MUTI_THREAD_MODE;
        }
    }

    print_info();
}

int bind_port() {
    #ifdef _WIN32

    WORD wVersion = MAKEWORD(2, 2); // 请求2.2版本的Winsock库
    WSADATA wsaData;
    if(WSAStartup(wVersion, &wsaData) != 0) {
        return FAIL;
    }

    client_socket = socket(AF_INET, SOCK_DGRAM, 0); // 创建UDP套接字
    server_socket = socket(AF_INET, SOCK_DGRAM, 0); 

    memset(&client_addr, 0, sizeof(client_addr)); // 初始化地址结构
    memset(&server_addr, 0, sizeof(server_addr));

    client_addr.sin_family = AF_INET; // 设置地址族
    client_addr.sin_addr.s_addr = INADDR_ANY; // 设置地址
    client_addr.sin_port = htons(port); // 设置端口

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
        if(debug_mode == DEBUG_MODE_2)
            printf("List size: %d\n", list_size);
        fclose(config_file_ptr);
        return SUCCESS;
    }
}

void add_host_info(char domain[], uint8_t IPAddr[]){ // 添加域名和IP地址到字典树
    if(list_size >= TRIE_LIST_SIZE - 1024) {
        debug_print("List size is almost full.");
        return;
    }
    int domain_len = strlen(domain);
    if(domain[domain_len - 1] != '.') {
        domain[domain_len] = '.';
        domain[domain_len + 1] = '\0';
        domain_len++;
    }
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

    if(mode == DEFAULT_MODE) { // 非阻塞模式
        /*一种简单的非阻塞模式，通过不断循环检查套接字的状态来接收数据*/

        u_long nonBlockingMode = 1;
        int ser_result = ioctlsocket(server_socket, FIONBIO, &nonBlockingMode); // 设置为非阻塞模式
        int cli_result = ioctlsocket(client_socket, FIONBIO, &nonBlockingMode);

        if(ser_result == SOCKET_ERROR || cli_result == SOCKET_ERROR) {
            printf("Set default mode failed.\n");
            closesocket(server_socket);
            closesocket(client_socket);
            WSACleanup();
            exit(1);
        }
        // success
        while (1) {
            receive_client();
            receive_server();
        }
    }
    else if(mode == POLL_MODE) { // 轮询模式
        /*使用 select 函数来监视多个套接字的状态，并在有数据时进行处理，减少了 CPU 占用*/

        fd_set readfds;
        struct timeval tv;
        
        while (1) {
            FD_ZERO(&readfds);
            FD_SET(client_socket, &readfds);
            FD_SET(server_socket, &readfds);

            // 设置超时时间
            tv.tv_sec = 0; // 秒
            tv.tv_usec = 50; // 微秒

            int poll_ret = select(0, &readfds, NULL, NULL, &tv);
            if (poll_ret == SOCKET_ERROR) {
                printf("ERROR WinSocketAPI Poll_mode: %d.\n", WSAGetLastError());
                closesocket(server_socket);
                closesocket(client_socket);
                WSACleanup();
                exit(1);
            }
            else if (poll_ret > 0) {
                if (FD_ISSET(client_socket, &readfds)) {
                    receive_client();
                }
                if (FD_ISSET(server_socket, &readfds)) {
                    receive_server();
                }
            }
        }
    }
    else if(mode == ASYNC_MODE) { // 异步模式
        /*使用 Windows 的异步消息机制，通过窗口消息来处理网络事件*/

        // 创建隐藏窗口
        // 程序创建一个隐藏窗口，并通过窗口过程函数 WindowProc 来处理异步消息。WindowProc 函数检查网络事件并调用相应的接收函数
        WNDCLASS wndClass = { 0 };
        wndClass.lpfnWndProc = WindowProc;
        wndClass.hInstance = GetModuleHandle(NULL);
        wndClass.lpszClassName = "AsyncSocketClass";
        RegisterClass(&wndClass);

        hwnd = CreateWindow("AsyncSocketClass", "AsyncSocketWindow", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, GetModuleHandle(NULL), NULL);

        if (!hwnd) {
            printf("CreateWindow failed.\n");
            WSACleanup();
            exit(1);
        }

        // 设置异步模式
        // 使用 WSAAsyncSelect 函数将套接字设置为异步模式。当指定的网络事件（如数据到达、连接关闭等）发生时，会向指定的窗口发送一个消息
        if (WSAAsyncSelect(server_socket, hwnd, WM_SOCKET, FD_READ | FD_CLOSE) == SOCKET_ERROR || WSAAsyncSelect(client_socket, hwnd, WM_SOCKET, FD_READ | FD_CLOSE) == SOCKET_ERROR) {
            printf("WSAAsyncSelect failed.\n");
            closesocket(server_socket);
            closesocket(client_socket);
            WSACleanup();
            DestroyWindow(hwnd);
            exit(1);
        }

        // 消息循环
        // 程序进入消息循环，通过 GetMessage、TranslateMessage 和 DispatchMessage 函数来处理消息
        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        DestroyWindow(hwnd);
    }
    else if(mode == MUTI_THREAD_MODE) { // 多线程模式
        u_long nonBlockingMode = 1;
        int ser_result = ioctlsocket(server_socket, FIONBIO, &nonBlockingMode);
        int cli_result = ioctlsocket(client_socket, FIONBIO, &nonBlockingMode);

        if(ser_result == SOCKET_ERROR || cli_result == SOCKET_ERROR) {
            printf("Set default mode failed.\n");
            closesocket(server_socket);
            closesocket(client_socket);
            WSACleanup();
            exit(1);
        }
        // success
        initThreadPool();
        while (1) {
            Thread_receive_client();
            Thread_receive_server();
        }
    }

    closesocket(server_socket);
    closesocket(client_socket);
    WSACleanup();
    return;

    #else

    #endif
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    if (uMsg == WM_SOCKET) {
        SOCKET sock = (SOCKET)wParam;
        int event = LOWORD(lParam);
        int error = HIWORD(lParam);

        if (error) {
            printf("Socket error: %d\n", error);
            closesocket(sock);
            WSACleanup();
            PostQuitMessage(1);
            return 0;
        }

        if (event & FD_READ) {
            if (sock == client_socket) {
                receive_client();
            } else if (sock == server_socket) {
                receive_server();
            }
        }

        if (event & FD_CLOSE) {
            closesocket(sock);
        }

        return 0;
    }

    return DefWindowProc(hwnd, uMsg, wParam, lParam);
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

void free_dns_struct(DNS_DATA* dns_data){
    if(dns_data->question != NULL){
        free(dns_data->question);
    }
    if(dns_data->answer != NULL){
        if(dns_data->header.ANCOUNT != 0){
            for (int i = 0; i < dns_data->header.ANCOUNT; i++){
                if(dns_data->answer[i].RDATA != NULL && dns_data->answer[i].RDLENGTH != 0){
                    free(dns_data->answer[i].RDATA);
                }
            }
            free(dns_data->answer);
        }
    }
    if(dns_data->authority != NULL){
        if(dns_data->header.NSCOUNT != 0){
            for (int i = 0; i < dns_data->header.NSCOUNT; i++){
                if(dns_data->authority[i].RDATA != NULL && dns_data->authority[i].RDLENGTH != 0){
                    free(dns_data->authority[i].RDATA);
                }
            }
            free(dns_data->authority);
        }
    }
    if(dns_data->additional != NULL){
        if(dns_data->header.ARCOUNT != 0){
            for (int i = 0; i < dns_data->header.ARCOUNT; i++){
                if(dns_data->additional[i].RDATA != NULL && dns_data->additional[i].RDLENGTH != 0){
                    free(dns_data->additional[i].RDATA);
                }
            }
            free(dns_data->additional);
        }
    }
    return;
}

void write_back_trie(char domain[], uint8_t ip_addr[], uint16_t QTYPE) {
    if(QTYPE == DNS_TYPE_AAAA){
        return;
    }
    else if(QTYPE == DNS_TYPE_A){
        debug_print("Ready to write back to trie.");
        if(debug_mode == DEBUG_MODE_2) {
            printf("Now List size: %d\n", list_size);
        }

        int pre_tire_list_size = list_size;
        add_host_info(domain, ip_addr);

        int now_tire_list_size = list_size;
        if(pre_tire_list_size != now_tire_list_size)
            write_back_file(domain, ip_addr, QTYPE);
        else
            debug_print("Already in the trie.");
        return;
    }
}

void write_back_file(char domain[], uint8_t ip_addr[], uint16_t QTYPE) {
    FILE* config_file_ptr = fopen(config_path, "a");
    if (!config_file_ptr || QTYPE == DNS_TYPE_AAAA) {
        return;
    }
    else {
        fseek(config_file_ptr, 0, SEEK_END); // 移动到文件末尾
        fprintf(config_file_ptr, "%hhu.%hhu.%hhu.%hhu %s\n", ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3], domain);
        debug_print("Write back to file.");
        fclose(config_file_ptr);
        return;
    }
}