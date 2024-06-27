#include "header.h"
#include "dns_data.h"

int cache_size = 0;
int addr_len = sizeof(struct sockaddr_in);
int is_listen = FALSE;
extern int char_map[256];

void receive_client() { //接收客户端DNS，查询，回复或上交远程DNS服务器处理
    char recv_buffer[BUFFER_SIZE];
    char ansTo_buffer[BUFFER_SIZE];
    DNS_DATA dns_msg;
    uint8_t ip_addr[16] = {0};
    int msg_size = -1;
    int ans_size = -1;
    int is_found = FALSE;

    msg_size = recvfrom(client_socket, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr*)&client_addr, &addr_len);

    if (msg_size > 0) {  //接收到请求响应
        get_dns_msg(recv_buffer, &dns_msg);
        debug_print("---------------------------");
        debug_print("Receive DNS request from client.");
        if(debug_mode == DEBUG_MODE_2){
            printf("Client IP: %s\t", inet_ntoa(client_addr.sin_addr));
            printf("Port: %d\n", ntohs(client_addr.sin_port));
        }
        if(debug_mode == DEBUG_MODE_2){
            for (int i = 0; i < msg_size; i++) {
                printf("%02x ", (unsigned char)recv_buffer[i]);
            }
            printf("\n");
        }
        debug_print_DNS(&dns_msg);

        for (int i = 0; i < dns_msg.header.QDCOUNT; i++){
            is_found = find_cache(dns_msg.question[i].QNAME, ip_addr, dns_msg.question[i].QTYPE);
            if (is_found == FAIL) {
                is_found = find_trie(dns_msg.question[i].QNAME, ip_addr, dns_msg.question[i].QTYPE);

                if(is_found == FAIL) {
                    //上交远程DNS服务器处理
                    uint16_t newID = set_ID(dns_msg.header.ID, client_addr);
                    if(newID >= (uint16_t)MAX_ID_LIST){
                        debug_print("ID list is full.");
                        free_dns_struct(&dns_msg);
                        return;
                    }
                    else{
                        newID = htons(newID);
                        memcpy(recv_buffer, &newID, sizeof(uint16_t));
                        sendto(server_socket, recv_buffer, msg_size, 0, (struct sockaddr*)&server_addr, addr_len);
                        is_listen = TRUE;
                        debug_print("Send DNS request to server.");
                        if(debug_mode == DEBUG_MODE_2)
                            printf("New ID: 0x%x\n", ntohs(newID));
                        debug_print("***************************");
                        free_dns_struct(&dns_msg);
                        return;
                    }
                }
                else{
                    if(ip_addr[0] == 0 && ip_addr[1] == 0 && ip_addr[2] == 0 && ip_addr[3] == 0) {
                        set_nodomain_ans(&dns_msg);
                        ans_size = set_dns_msg(ansTo_buffer, &dns_msg);
                        sendto(client_socket, ansTo_buffer, ans_size, 0, (struct sockaddr*)&client_addr, addr_len);
                        debug_print("Send DNS NODOAMIN response to client.");
                        debug_print("***************************");
                        free_dns_struct(&dns_msg);
                        return;
                    }
                    else
                        set_dns_ans(&dns_msg, ip_addr, dns_msg.question[i].QNAME, dns_msg.question[i].QTYPE);
                }
            }
            else{
                if(ip_addr[0] == 0 && ip_addr[1] == 0 && ip_addr[2] == 0 && ip_addr[3] == 0) {
                    set_nodomain_ans(&dns_msg);
                    ans_size = set_dns_msg(ansTo_buffer, &dns_msg);
                    sendto(client_socket, ansTo_buffer, ans_size, 0, (struct sockaddr*)&client_addr, addr_len);
                    debug_print("Send DNS NODOAMIN response to client.");
                    debug_print("***************************");
                    free_dns_struct(&dns_msg);
                    return;
                }
                else
                    set_dns_ans(&dns_msg, ip_addr, dns_msg.question[i].QNAME, dns_msg.question[i].QTYPE);
            }
        }

        if(dns_msg.header.ANCOUNT > 0) {
            ans_size = set_dns_msg(ansTo_buffer, &dns_msg);
            sendto(client_socket, ansTo_buffer, ans_size, 0, (struct sockaddr*)&client_addr, addr_len);
            debug_print("Send DNS response to client.");

            if(debug_mode == DEBUG_MODE_2){
                printf("DNS response Message Size: %d\n", ans_size);
                for (int i = 0; i < ans_size; i++) {
                    printf("%02x ", (unsigned char)ansTo_buffer[i]);
                }
                printf("\n");
            }
        }
        debug_print("***************************");
        free_dns_struct(&dns_msg);
    }
    return;
}

void receive_server() {
    uint8_t buffer[BUFFER_SIZE];
    DNS_DATA dns_msg;
    int msg_size = -1;

    if(is_listen == TRUE) {
        msg_size = recvfrom(server_socket, buffer, sizeof(buffer), 0, (struct sockaddr*)&server_addr, &addr_len);
    }

    if(is_listen == TRUE && msg_size > 0){
        get_dns_msg(buffer, &dns_msg);
        debug_print("---------------------------");
        debug_print("Receive DNS response from server.");
        if(debug_mode == DEBUG_MODE_2){
            printf("Server IP: %s\t", inet_ntoa(server_addr.sin_addr));
            printf("Port: %d\n", ntohs(server_addr.sin_port));
        }
        if(debug_mode == DEBUG_MODE_2){
            for (int i = 0; i < msg_size; i++) {
                printf("%02x ", (unsigned char)buffer[i]);
            }
            printf("\n");
        }
        debug_print_DNS(&dns_msg);
        uint16_t ID = dns_msg.header.ID;
        uint16_t Old_ID = htons(ID_list[ID].client_ID);
        ID_list[ID].expire_time = 0;
        memcpy(buffer, &Old_ID, sizeof(uint16_t));

        sendto(client_socket, buffer, msg_size, 0, (struct sockaddr*)&(ID_list[ID].client_addr), addr_len);
        debug_print("Send DNS response to client.");
        if(debug_mode == DEBUG_MODE_2){
            printf("Client IP: %s\t", inet_ntoa(ID_list[ID].client_addr.sin_addr));
            printf("Port: %d\n", ntohs(ID_list[ID].client_addr.sin_port));
            printf("ID: 0x%x\n", ntohs(Old_ID));
            for (int i = 0; i < msg_size; i++) {
                printf("%02x ", (unsigned char)buffer[i]);
            }
            printf("\n");
        }
        is_listen = FALSE;

        //更新缓存
        for (int i = 0; i < dns_msg.header.ANCOUNT; i++) {
            if(dns_msg.answer[i].CLASS == DNS_CLASS_IN && ((dns_msg.answer[i].TYPE == DNS_TYPE_A && dns_msg.answer[i].RDLENGTH == 4) || (dns_msg.answer[i].TYPE == DNS_TYPE_AAAA && dns_msg.answer[i].RDLENGTH == 16)))
                update_cache(dns_msg.answer[i].RDATA, dns_msg.answer[i].NAME, dns_msg.answer[i].TYPE);
        }
        debug_print("***************************");
        free_dns_struct(&dns_msg);
    }
    return;
}

void get_dns_msg(char recv_buffer[], DNS_DATA* dns_msg) {
    //DNS_HEADER
    dns_msg->header.ID = ntohs(*(uint16_t*)recv_buffer);
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

    // 动态分配DNS_QUESTION数组
    dns_msg->question = (struct DNS_QUESTION*)malloc(dns_msg->header.QDCOUNT * sizeof(struct DNS_QUESTION));
    if (!dns_msg->question) {
        debug_print("Memory allocation failed for DNS questions.");
        return;
    }
    if(dns_msg->header.QDCOUNT == 0)
        dns_msg->question = NULL;

    char *ptr_from_question = recv_buffer + 12; //跳过DNS_HEADER部分,指向DNS_QUESTION部分
    // 解析 DNS_QUESTION
    for (int i = 0; i < dns_msg->header.QDCOUNT; i++) {
        dns_msg->question[i].QNAME[0] = '\0'; // 初始化 QNAME 字符串
        int len = 0;
        while (*ptr_from_question != 0) {
            len = *ptr_from_question;
            strncat(dns_msg->question[i].QNAME, ptr_from_question + 1, len);
            strcat(dns_msg->question[i].QNAME, ".");
            ptr_from_question += len + 1;
        }
        ptr_from_question++; // 跳过 QNAME 末尾的 0 字节
        dns_msg->question[i].QTYPE = ntohs(*(uint16_t*)ptr_from_question);
        dns_msg->question[i].QCLASS = ntohs(*(uint16_t*)(ptr_from_question + 2));
        ptr_from_question += 4;
    }

    //DNS_ANSWER
    // 动态分配DNS_ANSWER数组
    dns_msg->answer = (struct DNS_RR*)malloc(dns_msg->header.ANCOUNT * sizeof(struct DNS_RR));
    if (!dns_msg->answer) {
        debug_print("Memory allocation failed for DNS answers.");
        return;
    }
    if(dns_msg->header.ANCOUNT == 0)
        dns_msg->answer = NULL;

    char *ptr_from_answer = ptr_from_question;
    for (int i = 0; i < dns_msg->header.ANCOUNT; i++) {
        dns_msg->answer[i].NAME[0] = '\0'; // 初始化 NAME 字符串
        int len = 0;
        /*
            若 NAME 字段高两位为 1，则表示该字段是一个指针，指向一个之前出现过的 QNAME 字段，指针指向的位置为指针的值加上 0xc000
            处理指针时，只需将指针的值减去 0xc000，然后跳转到该位置继续解析即可
        */
        if ((*ptr_from_answer & 0xc0) == 0xc0) {
            uint16_t offset = ntohs(*(uint16_t*)ptr_from_answer) & 0x3fff;
            char *ptr = recv_buffer + offset;
            while (*ptr != 0) {
                len = *ptr;
                strncat(dns_msg->answer[i].NAME, ptr + 1, len);
                strcat(dns_msg->answer[i].NAME, ".");
                ptr += len + 1;
            }
            ptr_from_answer += 2;
        }
        else {
            while (*ptr_from_answer != 0) {
                len = *ptr_from_answer;
                strncat(dns_msg->answer[i].NAME, ptr_from_answer + 1, len);
                strcat(dns_msg->answer[i].NAME, ".");
                ptr_from_answer += len + 1;
            }
            ptr_from_answer++;
        }
        dns_msg->answer[i].TYPE = ntohs(*(uint16_t*)ptr_from_answer);
        dns_msg->answer[i].CLASS = ntohs(*(uint16_t*)(ptr_from_answer + 2));
        dns_msg->answer[i].TTL = ntohl(*(uint32_t*)(ptr_from_answer + 4));
        ptr_from_answer += 8;

        dns_msg->answer[i].RDLENGTH = ntohs(*(uint16_t*)ptr_from_answer);
        dns_msg->answer[i].RDATA = (uint8_t*)malloc(dns_msg->answer[i].RDLENGTH);
        if (!dns_msg->answer[i].RDATA) {
            debug_print("Memory allocation failed for DNS RDATA.");
            return;
        }
        memcpy(dns_msg->answer[i].RDATA, ptr_from_answer + 2, dns_msg->answer[i].RDLENGTH);
        if(dns_msg->answer[i].RDLENGTH == 0)
            dns_msg->answer[i].RDATA = NULL;
        ptr_from_answer += 2 + dns_msg->answer[i].RDLENGTH;
    }

    //DNS_AUTHORITY
    dns_msg->authority = (struct DNS_RR*)malloc(dns_msg->header.NSCOUNT * sizeof(struct DNS_RR));
    if (!dns_msg->authority) {
        debug_print("Memory allocation failed for DNS authority.");
        return;
    }
    if(dns_msg->header.NSCOUNT == 0)
        dns_msg->authority = NULL;

    char *ptr_from_authority = ptr_from_answer;
    for (int i = 0; i < dns_msg->header.NSCOUNT; i++) {
        dns_msg->authority[i].NAME[0] = '\0'; // 初始化 NAME 字符串
        int len = 0;
        if((*ptr_from_authority & 0xc0) == 0xc0) {
            uint16_t offset = ntohs(*(uint16_t*)ptr_from_authority) & 0x3fff;
            char *ptr = recv_buffer + offset;
            while (*ptr != 0) {
                len = *ptr;
                strncat(dns_msg->authority[i].NAME, ptr + 1, len);
                strcat(dns_msg->authority[i].NAME, ".");
                ptr += len + 1;
            }
            ptr_from_authority += 2;
        }
        else {
            while (*ptr_from_authority != 0) {
                len = *ptr_from_authority;
                strncat(dns_msg->authority[i].NAME, ptr_from_authority + 1, len);
                strcat(dns_msg->authority[i].NAME, ".");
                ptr_from_authority += len + 1;
            }
            ptr_from_authority++;
        }
        dns_msg->authority[i].TYPE = ntohs(*(uint16_t*)ptr_from_authority);
        dns_msg->authority[i].CLASS = ntohs(*(uint16_t*)(ptr_from_authority + 2));
        dns_msg->authority[i].TTL = ntohl(*(uint32_t*)(ptr_from_authority + 4));
        ptr_from_authority += 8;

        dns_msg->authority[i].RDLENGTH = ntohs(*(uint16_t*)ptr_from_authority);
        dns_msg->authority[i].RDATA = (uint8_t*)malloc(dns_msg->authority[i].RDLENGTH);
        if (!dns_msg->authority[i].RDATA) {
            debug_print("Memory allocation failed for DNS RDATA.");
            return;
        }
        memcpy(dns_msg->authority[i].RDATA, ptr_from_authority + 2, dns_msg->authority[i].RDLENGTH);
        if(dns_msg->authority[i].RDLENGTH == 0)
            dns_msg->authority[i].RDATA = NULL;
        ptr_from_authority += 2 + dns_msg->authority[i].RDLENGTH;
    }

    //DNS_ADDITIONAL
    dns_msg->additional = (struct DNS_RR*)malloc(dns_msg->header.ARCOUNT * sizeof(struct DNS_RR));
    if (!dns_msg->additional) {
        debug_print("Memory allocation failed for DNS additional.");
        return;
    }
    if(dns_msg->header.ARCOUNT == 0)
        dns_msg->additional = NULL;

    char *ptr_from_additional = ptr_from_authority;
    for (int i = 0; i < dns_msg->header.ARCOUNT; i++) {
        dns_msg->additional[i].NAME[0] = '\0'; // 初始化 NAME 字符串
        int len = 0;
        if((*ptr_from_additional & 0xc0) == 0xc0) {
            uint16_t offset = ntohs(*(uint16_t*)ptr_from_additional) & 0x3fff;
            char *ptr = recv_buffer + offset;
            while (*ptr != 0) {
                len = *ptr;
                strncat(dns_msg->additional[i].NAME, ptr + 1, len);
                strcat(dns_msg->additional[i].NAME, ".");
                ptr += len + 1;
            }
            ptr_from_additional += 2;
        }
        else {
            while (*ptr_from_additional != 0) {
                len = *ptr_from_additional;
                strncat(dns_msg->additional[i].NAME, ptr_from_additional + 1, len);
                strcat(dns_msg->additional[i].NAME, ".");
                ptr_from_additional += len + 1;
            }
            ptr_from_additional++;
        }
        dns_msg->additional[i].TYPE = ntohs(*(uint16_t*)ptr_from_additional);
        dns_msg->additional[i].CLASS = ntohs(*(uint16_t*)(ptr_from_additional + 2));
        dns_msg->additional[i].TTL = ntohl(*(uint32_t*)(ptr_from_additional + 4));
        ptr_from_additional += 8;

        dns_msg->additional[i].RDLENGTH = ntohs(*(uint16_t*)ptr_from_additional);
        dns_msg->additional[i].RDATA = (uint8_t*)malloc(dns_msg->additional[i].RDLENGTH);
        if (!dns_msg->additional[i].RDATA) {
            debug_print("Memory allocation failed for DNS RDATA.");
            return;
        }
        memcpy(dns_msg->additional[i].RDATA, ptr_from_additional + 2, dns_msg->additional[i].RDLENGTH);
        if(dns_msg->additional[i].RDLENGTH == 0)
            dns_msg->additional[i].RDATA = NULL;
        ptr_from_additional += 2 + dns_msg->additional[i].RDLENGTH;
    }

    return;
}

void set_dns_ans(DNS_DATA* dns_msg, uint8_t ip_addr[], char name[], uint16_t QTYPE) {
    dns_msg->header.QR = 1;
    dns_msg->header.RCODE = DNS_RCODE_NO_ERROR;
    dns_msg->header.ANCOUNT++;
    if(dns_msg->answer == NULL)
        dns_msg->answer = malloc(sizeof(struct DNS_RR) * dns_msg->header.ANCOUNT);
    else
        dns_msg->answer = realloc(dns_msg->answer, sizeof(struct DNS_RR) * dns_msg->header.ANCOUNT);

    strcpy(dns_msg->answer[dns_msg->header.ANCOUNT - 1].NAME, name);
    dns_msg->answer[dns_msg->header.ANCOUNT - 1].TYPE = QTYPE;
    dns_msg->answer[dns_msg->header.ANCOUNT - 1].CLASS = DNS_CLASS_IN;
    dns_msg->answer[dns_msg->header.ANCOUNT - 1].TTL = 300;
    dns_msg->answer[dns_msg->header.ANCOUNT - 1].RDLENGTH = QTYPE == DNS_TYPE_AAAA ? 16 : 4;
    dns_msg->answer[dns_msg->header.ANCOUNT - 1].RDATA = malloc(sizeof(uint8_t) * (QTYPE == DNS_TYPE_AAAA ? 16 : 4));
    memcpy(dns_msg->answer[dns_msg->header.ANCOUNT - 1].RDATA, ip_addr, sizeof(uint8_t) * (QTYPE == DNS_TYPE_AAAA ? 16 : 4));
    return;
}

int set_dns_msg(char ansTo_buffer[], DNS_DATA* dns_msg) {
    int total_len = 0;
    //设置DNS_HEADER
    *(uint16_t*)(ansTo_buffer) = htons(dns_msg->header.ID);
    ansTo_buffer[2] = (dns_msg->header.QR << 7) + (dns_msg->header.OPCODE << 3) + (dns_msg->header.AA << 2) + (dns_msg->header.TC << 1) + dns_msg->header.RD;
    ansTo_buffer[3] = (dns_msg->header.RA << 7) + (dns_msg->header.Z << 4) + dns_msg->header.RCODE;
    *(uint16_t*)(ansTo_buffer + 4) = htons(dns_msg->header.QDCOUNT);
    *(uint16_t*)(ansTo_buffer + 6) = htons(dns_msg->header.ANCOUNT);
    *(uint16_t*)(ansTo_buffer + 8) = htons(dns_msg->header.NSCOUNT);
    *(uint16_t*)(ansTo_buffer + 10) = htons(dns_msg->header.ARCOUNT);
    total_len += 12;

    //设置DNS_QUESTION
    char *ptr_to_question = ansTo_buffer + 12;
    for (int i = 0; i < dns_msg->header.QDCOUNT; i++) {
        char *ptr_to_name = dns_msg->question[i].QNAME;
        int name_len = strlen(ptr_to_name);
        int pos = 0;
        while (pos < name_len) {
            int label_len = strchr(ptr_to_name + pos, '.') - (ptr_to_name + pos); // 获取标签长度
            *ptr_to_question++ = label_len; // 写入标签长度
            memcpy(ptr_to_question, ptr_to_name + pos, label_len); // 写入标签
            ptr_to_question += label_len;
            pos += label_len + 1;
        }
        *ptr_to_question++ = 0; // 结束标志
        *(uint16_t*)ptr_to_question = htons(dns_msg->question[i].QTYPE);
        ptr_to_question += 2;
        *(uint16_t*)ptr_to_question = htons(dns_msg->question[i].QCLASS);
        ptr_to_question += 2;

        total_len += name_len + 1 + 2 + 2;
    }   

    //设置DNS_ANSWER
    char *ptr_to_answer = ptr_to_question;
    for (int i = 0; i < dns_msg->header.ANCOUNT; i++) {
        char *ptr_to_name = dns_msg->answer[i].NAME;
        int name_len = strlen(ptr_to_name);
        int pos = 0;
        while (pos < name_len) {
            int label_len = strchr(ptr_to_name + pos, '.') - (ptr_to_name + pos); // 获取标签长度
            *ptr_to_answer++ = label_len; // 写入标签长度
            memcpy(ptr_to_answer, ptr_to_name + pos, label_len); // 写入标签
            ptr_to_answer += label_len;
            pos += label_len + 1;
        }
        *ptr_to_answer++ = 0; // 结束标志
        *(uint16_t*)ptr_to_answer = htons(dns_msg->answer[i].TYPE);
        ptr_to_answer += 2;
        *(uint16_t*)ptr_to_answer = htons(dns_msg->answer[i].CLASS);
        ptr_to_answer += 2;
        *(uint32_t*)ptr_to_answer = htonl(dns_msg->answer[i].TTL);
        ptr_to_answer += 4;
        *(uint16_t*)ptr_to_answer = htons(dns_msg->answer[i].RDLENGTH);
        ptr_to_answer += 2;
        memcpy(ptr_to_answer, dns_msg->answer[i].RDATA, dns_msg->answer[i].RDLENGTH);
        ptr_to_answer += dns_msg->answer[i].RDLENGTH;

        total_len += name_len + 1 + 2 + 2 + 4 + 2 + dns_msg->answer[i].RDLENGTH;
    }

    //设置DNS_AUTHORITY
    char *ptr_to_authority = ptr_to_answer;
    for (int i = 0; i < dns_msg->header.NSCOUNT; i++) {
        char *ptr_to_name = dns_msg->authority[i].NAME;
        int name_len = strlen(ptr_to_name);
        int pos = 0;
        while (pos < name_len) {
            int label_len = strchr(ptr_to_name + pos, '.') - (ptr_to_name + pos); // 获取标签长度
            *ptr_to_authority++ = label_len; // 写入标签长度
            memcpy(ptr_to_authority, ptr_to_name + pos, label_len); // 写入标签
            ptr_to_authority += label_len;
            pos += label_len + 1;
        }
        *ptr_to_authority++ = 0; // 结束标志
        *(uint16_t*)ptr_to_authority = htons(dns_msg->authority[i].TYPE);
        ptr_to_authority += 2;
        *(uint16_t*)ptr_to_authority = htons(dns_msg->authority[i].CLASS);
        ptr_to_authority += 2;
        *(uint32_t*)ptr_to_authority = htonl(dns_msg->authority[i].TTL);
        ptr_to_authority += 4;
        *(uint16_t*)ptr_to_authority = htons(dns_msg->authority[i].RDLENGTH);
        ptr_to_authority += 2;
        memcpy(ptr_to_authority, dns_msg->authority[i].RDATA, dns_msg->authority[i].RDLENGTH);
        ptr_to_authority += dns_msg->authority[i].RDLENGTH;

        total_len += name_len + 1 + 2 + 2 + 4 + 2 + dns_msg->authority[i].RDLENGTH;
    }

    //设置DNS_ADDITIONAL
    char *ptr_to_additional = ptr_to_authority;
    for (int i = 0; i < dns_msg->header.ARCOUNT; i++) {
        char *ptr_to_name = dns_msg->additional[i].NAME;
        int name_len = strlen(ptr_to_name);
        int pos = 0;
        while (pos < name_len) {
            int label_len = strchr(ptr_to_name + pos, '.') - (ptr_to_name + pos);
            *ptr_to_additional++ = label_len;
            memcpy(ptr_to_additional, ptr_to_name + pos, label_len);
            ptr_to_additional += label_len;
            pos += label_len + 1;
        }
        *ptr_to_additional++ = 0; // 结束标志
        *(uint16_t*)ptr_to_additional = htons(dns_msg->additional[i].TYPE);
        ptr_to_additional += 2;
        *(uint16_t*)ptr_to_additional = htons(dns_msg->additional[i].CLASS);
        ptr_to_additional += 2;
        *(uint32_t*)ptr_to_additional = htonl(dns_msg->additional[i].TTL);
        ptr_to_additional += 4;
        *(uint16_t*)ptr_to_additional = htons(dns_msg->additional[i].RDLENGTH);
        ptr_to_additional += 2;
        memcpy(ptr_to_additional, dns_msg->additional[i].RDATA, dns_msg->additional[i].RDLENGTH);
        ptr_to_additional += dns_msg->additional[i].RDLENGTH;

        total_len += name_len + 1 + 2 + 2 + 4 + 2 + dns_msg->additional[i].RDLENGTH;
    }
    return total_len;
}

int find_cache(char domain[], uint8_t ip_addr[], uint16_t QTYPE) {
    struct lru_node* ptr = lru_head;

    if (QTYPE != DNS_TYPE_A && QTYPE != DNS_TYPE_AAAA) {
        debug_print("Domain not found in cache.");
        return FAIL;
    }
    if (cache_size == 0) {
        debug_print("Domain not found in cache.");
        return FAIL;
    }

    while (ptr->next != NULL) {
        if (strcmp(ptr->next->domain, domain) == 0) {
            if(debug_mode == DEBUG_MODE_2) {
                printf("%s", ptr->next->domain);
                if (ptr->next->is_IPv6 == FALSE){
                    printf("\tIPv4: %d.%d.%d.%d\n", ptr->next->IP[0], ptr->next->IP[1], ptr->next->IP[2], ptr->next->IP[3]);
                }
                else if (ptr->next->is_IPv6 == TRUE){
                    printf("\tIPv6: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n", ptr->next->IP[0], ptr->next->IP[1], ptr->next->IP[2], ptr->next->IP[3], ptr->next->IP[4], ptr->next->IP[5], ptr->next->IP[6], ptr->next->IP[7], ptr->next->IP[8], ptr->next->IP[9], ptr->next->IP[10], ptr->next->IP[11], ptr->next->IP[12], ptr->next->IP[13], ptr->next->IP[14], ptr->next->IP[15]);
                }
            }
            if (QTYPE == DNS_TYPE_A && ptr->next->is_IPv6 == FALSE) {
                memcpy(ip_addr, ptr->next->IP, sizeof(ptr->next->IP));
            }
            else if (QTYPE == DNS_TYPE_AAAA && ptr->next->is_IPv6 == TRUE) {
                memcpy(ip_addr, ptr->next->IP, sizeof(ptr->next->IP));
            }
            else if (ptr->next->is_IPv6 == FALSE && ptr->next->IP[0] == 0 && ptr->next->IP[1] == 0 && ptr->next->IP[2] == 0 && ptr->next->IP[3] == 0) {
                memcpy(ip_addr, ptr->next->IP, sizeof(ptr->next->IP));
            }
            else {
                ptr = ptr->next;
                continue;
            }

            //LRU机制，最近访问的放到头部
            struct lru_node* temp = ptr->next;
            ptr->next = temp->next;
            temp->next = lru_head->next;
            lru_head->next = temp;

            debug_print("Find domain in cache.");
            return SUCCESS;
        }
        else {
            ptr = ptr->next;
        }
    }
    debug_print("Domain not found in cache.");
    return FAIL;
}

void update_cache(uint8_t ip_addr[], char domain[], uint16_t QTYPE) {
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
    new_node->is_IPv6 = (QTYPE == DNS_TYPE_AAAA) ? TRUE : FALSE;
    memcpy(new_node->IP, ip_addr, sizeof(uint8_t) * (new_node->is_IPv6 ? 16 : 4));
    strcpy(new_node->domain, domain);

    //LRU机制，最近访问的放到头部
    new_node->next = lru_head->next;
    lru_head->next = new_node;
}

int find_trie(char domain[], uint8_t ip_addr[], uint16_t QTYPE) {
    if(QTYPE != DNS_TYPE_A && QTYPE != DNS_TYPE_AAAA) {
        debug_print("Only IP Address is supported in host trie.");
        return FAIL;
    }
    int domain_len = strlen(domain);
    int index = 0;

    for (int i = 0; i < domain_len; i++) {
        int num = char_map[domain[i]];

        if (list_trie[index].val[num] == 0) {
            debug_print("Domain not found in host trie.");
            return FAIL;
        }
        index = list_trie[index].val[num];
    }

    if (list_trie[index].isEnd == TRUE) {
        debug_print("Find domain in host trie.");
        if(debug_mode == DEBUG_MODE_2) {
            printf("%s", domain);
            printf("\t%d %d %d %d\n", list_trie[index].IP[0], list_trie[index].IP[1], list_trie[index].IP[2], list_trie[index].IP[3]);
        }
        if (QTYPE == DNS_TYPE_AAAA && !(list_trie[index].IP[0] == 0 && list_trie[index].IP[1] == 0 && list_trie[index].IP[2] == 0 && list_trie[index].IP[3] == 0)) {
            debug_print("IPv6 not support in host trie.");
            return FAIL;
        }

        update_cache(list_trie[index].IP, domain, QTYPE);
        memcpy(ip_addr, list_trie[index].IP, sizeof(list_trie[index].IP));
        return SUCCESS;
    }
    else {
        debug_print("Domain not found in host trie.");
        return FAIL;
    }
}

uint16_t set_ID(uint16_t client_ID, struct sockaddr_in client_address) {
    uint16_t newID = 1;
    for (newID = 1; newID < MAX_ID_LIST; newID++) {
        if(ID_list[newID].expire_time < time(NULL)) {
            ID_list[newID].client_ID = client_ID;
            ID_list[newID].client_addr = client_address;
            ID_list[newID].expire_time = time(NULL) + 4;
            break;
        }
    }
    return newID;
}

void debug_print_DNS(const DNS_DATA* dns_msg) {
    if (debug_mode == NO_DEBUG)
        return;
    else if (debug_mode == DEBUG_MODE_1){
        time_t currentTime = time(NULL);
        printf("ID: 0x%x\t", dns_msg->header.ID);
        printf("Time: %s", ctime(&currentTime));
        for (int i = 0; i < dns_msg->header.QDCOUNT; i++){
            printf("DOMAIN: %s\n", dns_msg->question[i].QNAME);
        }
        for (int i = 0; i < dns_msg->header.ANCOUNT; i++){
            printf("NAME: %s\n", dns_msg->answer[i].NAME);
            printf("RDATA: ");
            for (int j = 0; j < dns_msg->answer[i].RDLENGTH; j++){
                printf("%u ", dns_msg->answer[i].RDATA[j]);
            }
        }
        return;
    }
    else if (debug_mode == DEBUG_MODE_2){
        time_t currentTime = time(NULL);
        printf("ID: 0x%x\t", dns_msg->header.ID);
        printf("Time: %s", ctime(&currentTime));
        printf("FLAGS: QR %d, OPCODE %d, AA %d, TC %d, RD %d, RA %d, Z %d, RCODE %d\n", dns_msg->header.QR, dns_msg->header.OPCODE, dns_msg->header.AA, dns_msg->header.TC, dns_msg->header.RD, dns_msg->header.RA, dns_msg->header.Z, dns_msg->header.RCODE);
        printf("QDCOUNT: %d, ANCOUNT: %d, NSCOUNT: %d, ARCOUNT: %d\n", dns_msg->header.QDCOUNT, dns_msg->header.ANCOUNT, dns_msg->header.NSCOUNT, dns_msg->header.ARCOUNT);
        for (int i = 0; i < dns_msg->header.QDCOUNT; i++){
            printf("DOMAIN: %s\t TYPE: %d\t CLASS: %d\n", dns_msg->question[i].QNAME, dns_msg->question[i].QTYPE, dns_msg->question[i].QCLASS);
        }
        for (int i = 0; i < dns_msg->header.ANCOUNT; i++){
            printf("NAME: %s\t TYPE: %d\t CLASS: %d\t TTL: %d\t RDLENGTH: %d\n", dns_msg->answer[i].NAME, dns_msg->answer[i].TYPE, dns_msg->answer[i].CLASS, dns_msg->answer[i].TTL, dns_msg->answer[i].RDLENGTH);
            printf("RDATA: ");
            for (int j = 0; j < dns_msg->answer[i].RDLENGTH; j++){
                printf("%u ", dns_msg->answer[i].RDATA[j]);
            }
            printf("\n");
        }
        return;
    }
}

void set_nodomain_ans(DNS_DATA* dns_msg){
    dns_msg->header.QR = 1;
    dns_msg->header.RCODE = DNS_RCODE_NAME_ERROR;
}