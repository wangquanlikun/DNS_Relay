#include "header.h"
#include "dns_data.h"

int cache_size = 0;
int addr_len = sizeof(struct sockaddr_in);
int listen_num = 0;
extern int char_map[256];

void receive_client() { //接收客户端DNS，查询，回复或上交远程DNS服务器处理
    char recv_buffer[BUFFER_SIZE];
    char ansTo_buffer[BUFFER_SIZE];
    DNS_DATA dns_msg;
    uint8_t ip_addr[4] = {0};
    int msg_size = -1;
    int is_found = FALSE;

    msg_size = recvfrom(client_socket, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr*)&client_addr, &addr_len);

    if (msg_size >= 0) {  //接收到请求响应
        get_dns_msg(recv_buffer, &dns_msg);
        debug_print("Receive DNS request from client.");
        
        struct DNS_QUESTION *temp = dns_msg.question;
        for(int i = 0; i < dns_msg.header.QDCOUNT; i++) {
            is_found = find_cache(temp->QNAME, ip_addr);
            if (is_found == FAIL) {
                debug_print("Domain not found in cache.");

                is_found = find_trie(temp->QNAME, ip_addr);
                if(is_found == FAIL) {
                    debug_print("Domain not found in host->trie.");

                    //上交远程DNS服务器处理
                    uint16_t newID = set_ID(dns_msg.header.ID, client_addr);
                    memcpy(recv_buffer, &newID, sizeof(uint16_t));
                    if(newID >= MAX_ID_LIST){
                        debug_print("ID list is full.");
                        return;
                    }
                    else{
                        sendto(server_socket, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr*)&server_addr, addr_len);
                        listen_num++;
                    }
                }
            }
            if(is_found)
                set_dns(&dns_msg, ip_addr);
            temp = temp->next;
        }
        set_dns_msg(ansTo_buffer, &dns_msg);
        if(dns_msg.header.ANCOUNT > 0) {
            sendto(client_socket, ansTo_buffer, sizeof(ansTo_buffer), 0, (struct sockaddr*)&client_addr, addr_len);
        }
    }
    return;
}

void receive_server() {
    uint8_t buffer[BUFFER_SIZE];
    DNS_DATA dns_msg;
    int msg_size = -1;

    if(listen_num > 0) {
        msg_size = recvfrom(server_socket, buffer, sizeof(buffer), 0, (struct sockaddr*)&server_addr, &addr_len);
        debug_print("Receive DNS response from server.");
        get_dns_msg(buffer, &dns_msg);
    }

    if(listen_num > 0 && msg_size > 0){
        uint16_t ID = dns_msg.header.ID;
        uint16_t Old_ID = htons(ID_list[ID].client_ID);
        ID_list[ID].expire_time = 0;
        memcpy(buffer, &Old_ID, sizeof(uint16_t));

        sendto(client_socket, buffer, msg_size, 0, (struct sockaddr*)&client_addr, addr_len);
        listen_num--;
    }
}

void get_dns_msg(char recv_buffer[], DNS_DATA* dns_msg) {
    //DNS_HEADER
    dns_msg->header.ID = (recv_buffer[0] << 8) + recv_buffer[1];
    dns_msg->header.QR = (recv_buffer[2] >> 7) & 0x01;
    dns_msg->header.OPCODE = (recv_buffer[2] >> 3) & 0x0F;
    dns_msg->header.AA = (recv_buffer[2] >> 2) & 0x01;
    dns_msg->header.TC = (recv_buffer[2] >> 1) & 0x01;
    dns_msg->header.RD = recv_buffer[2] & 0x01;
    dns_msg->header.RA = (recv_buffer[3] >> 7) & 0x01;
    dns_msg->header.Z = (recv_buffer[3] >> 4) & 0x07;
    dns_msg->header.RCODE = recv_buffer[3] & 0x0F;
    dns_msg->header.QDCOUNT = (recv_buffer[4] << 8) + recv_buffer[5];
    dns_msg->header.ANCOUNT = (recv_buffer[6] << 8) + recv_buffer[7];
    dns_msg->header.NSCOUNT = (recv_buffer[8] << 8) + recv_buffer[9];
    dns_msg->header.ARCOUNT = (recv_buffer[10] << 8) + recv_buffer[11];

    //DNS_QUESTION
    dns_msg->question = (struct DNS_QUESTION*)malloc(sizeof(struct DNS_QUESTION));
    char *ptr_from_question = recv_buffer + 12;
    for (int i = 0; i < dns_msg->header.QDCOUNT; i++) {
        struct DNS_QUESTION *temp = malloc(sizeof(struct DNS_QUESTION));
        strcpy(temp->QNAME, ptr_from_question);
        temp->QTYPE = (ptr_from_question + strlen(ptr_from_question) + 1)[0] << 8 + (ptr_from_question + strlen(ptr_from_question) + 1)[1];
        temp->QCLASS = (ptr_from_question + strlen(ptr_from_question) + 3)[0] << 8 + (ptr_from_question + strlen(ptr_from_question) + 3)[1];
        ptr_from_question += strlen(ptr_from_question) + 5;

        temp->next = dns_msg->question;
        dns_msg->question = temp;
    }

    //DNS_ANSWER
    dns_msg->answer = (struct DNS_RR*)malloc(sizeof(struct DNS_RR));
    char *ptr_from_answer = ptr_from_question;
    for (int i = 0; i < dns_msg->header.ANCOUNT; i++) {
        struct DNS_RR *temp = malloc(sizeof(struct DNS_RR));
        strcpy(temp->NAME, ptr_from_answer);
        temp->TYPE = (ptr_from_answer + strlen(ptr_from_answer) + 1)[0] << 8 + (ptr_from_answer + strlen(ptr_from_answer) + 1)[1];
        temp->CLASS = (ptr_from_answer + strlen(ptr_from_answer) + 3)[0] << 8 + (ptr_from_answer + strlen(ptr_from_answer) + 3)[1];
        temp->TTL = (ptr_from_answer + strlen(ptr_from_answer) + 5)[0] << 24 + (ptr_from_answer + strlen(ptr_from_answer) + 5)[1] << 16 + (ptr_from_answer + strlen(ptr_from_answer) + 5)[2] << 8 + (ptr_from_answer + strlen(ptr_from_answer) + 5)[3];
        temp->RDLENGTH = (ptr_from_answer + strlen(ptr_from_answer) + 9)[0] << 8 + (ptr_from_answer + strlen(ptr_from_answer) + 9)[1];
        temp->RDATA = (uint8_t*)(ptr_from_answer + strlen(ptr_from_answer) + 11);
        ptr_from_answer += strlen(ptr_from_answer) + 11 + temp->RDLENGTH;

        temp->next = dns_msg->answer;
        dns_msg->answer = temp;
    }

    //DNS_AUTHORITY
    dns_msg->authority = (struct DNS_RR*)malloc(sizeof(struct DNS_RR));
    char *ptr_from_authority = ptr_from_answer;
    for (int i = 0; i < dns_msg->header.NSCOUNT; i++) {
        struct DNS_RR *temp = malloc(sizeof(struct DNS_RR));
        strcpy(temp->NAME, ptr_from_authority);
        temp->TYPE = (ptr_from_authority + strlen(ptr_from_authority) + 1)[0] << 8 + (ptr_from_authority + strlen(ptr_from_authority) + 1)[1];
        temp->CLASS = (ptr_from_authority + strlen(ptr_from_authority) + 3)[0] << 8 + (ptr_from_authority + strlen(ptr_from_authority) + 3)[1];
        temp->TTL = (ptr_from_authority + strlen(ptr_from_authority) + 5)[0] << 24 + (ptr_from_authority + strlen(ptr_from_authority) + 5)[1] << 16 + (ptr_from_authority + strlen(ptr_from_authority) + 5)[2] << 8 + (ptr_from_authority + strlen(ptr_from_authority) + 5)[3];
        temp->RDLENGTH = (ptr_from_authority + strlen(ptr_from_authority) + 9)[0] << 8 + (ptr_from_authority + strlen(ptr_from_authority) + 9)[1];
        temp->RDATA = (uint8_t*)(ptr_from_authority + strlen(ptr_from_authority) + 11);
        ptr_from_authority += strlen(ptr_from_authority) + 11 + temp->RDLENGTH;

        temp->next = dns_msg->authority;
        dns_msg->authority = temp;
    }

    return;
}

void set_dns(DNS_DATA* dns_msg, uint8_t ip_addr[]) {}

void set_dns_msg(char ansTo_buffer[], DNS_DATA* dns_msg) {}

int find_cache(char domain[], uint8_t ip_addr[]) {
    struct lru_node* ptr = lru_head;

    while (ptr->next != NULL) {
        if (strcmp(ptr->next->domain, domain) == 0) {
            debug_print("Find domain in cache.");
            if(debug_mode == DEBUG_MODE_2) {
                printf("%s", ptr->next->domain);
                printf("\t%d %d %d %d\n", ptr->next->IP[0], ptr->next->IP[1], ptr->next->IP[2], ptr->next->IP[3]);
            }
            memcpy(ip_addr, ptr->next->IP, sizeof(ptr->next->IP));

            //LRU机制，最近访问的放到头部
            struct lru_node* temp = ptr->next;
            ptr->next = temp->next;
            temp->next = lru_head->next;
            lru_head->next = temp;

            return SUCCESS;
        }
        else {
            ptr = ptr->next;
        }
    }
    return FAIL;
}

void update_cache(uint8_t ip_addr[4], char domain[]) {
    struct lru_node* new_node = malloc(sizeof(LRU_NODE));
    
    if(cache_size >= MAX_CACHE_SIZE) {
        LRU_NODE* ptr = lru_head;
        while(ptr->next->next != NULL) {
            ptr = ptr->next;
        }
        free(ptr->next);
        ptr->next = NULL;
    }

    cache_size++;
    memcpy(new_node->IP, ip_addr, sizeof(uint8_t) * 4);
    strcpy(new_node->domain, domain);

    //LRU机制，最近访问的放到头部
    new_node->next = lru_head->next;
    lru_head->next = new_node;
}

int find_trie(char domain[], uint8_t ip_addr[]) {
    int domain_len = strlen(domain);
    int index = 0;

    for (int i = 0; i < domain_len; i++) {
        int num = char_map[domain[i]];

        if (list_trie[index].val[num] == 0) {
            debug_print("Domain not found in host->trie.");
            return FAIL;
        }
        index = list_trie[index].val[num];
    }

    if (list_trie[index].isEnd == TRUE) {
        debug_print("Find domain in host->trie.");
        if(debug_mode == DEBUG_MODE_2) {
            printf("%s", domain);
            printf("\t%d %d %d %d\n", list_trie[index].IP[0], list_trie[index].IP[1], list_trie[index].IP[2], list_trie[index].IP[3]);
        }

        update_cache(list_trie[index].IP, domain);
        memcpy(ip_addr, list_trie[index].IP, sizeof(list_trie[index].IP));
        return SUCCESS;
    }
    else {
        debug_print("Domain not found in host->trie.");
        return FAIL;
    }
}

uint16_t set_ID(uint16_t client_ID, struct sockaddr_in client_address) {
    uint16_t newID = 0;
    for (newID = 0; newID < MAX_ID_LIST; newID++) {
        if(ID_list[newID].expire_time < time(NULL)) {
            ID_list[newID].client_ID = client_ID;
            ID_list[newID].client_addr = client_address;
            ID_list[newID].expire_time = time(NULL) + 10;
            break;
        }
    }
    return newID;
}