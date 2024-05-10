#include "header.h"
#include "dns_data.h"

int cache_size = 0;
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
        get_dns_msg(recv_buffer, &dns_msg);
        debug_print("Receive DNS request from client.");
        
    }
}

void receive_server() {

}

void get_dns_msg(char recv_buffer[], DNS_DATA* dns_msg) {}

void set_dns_msg(char ansTo_buffer[], DNS_DATA* dns_msg, uint8_t ip_addr[]) {}

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
    memcpy(new_node->IP, ip_addr, sizeof(ip_addr));
    strcpy(new_node->domain, domain);

    //LRU机制，最近访问的放到头部
    new_node->next = lru_head->next;
    lru_head->next = new_node;
}

int find_trie(char domain[], uint8_t ip_addr[]) {
    int domain_len = strlen(domain);
    int index = 0;

    for (int i = 0; i < domain_len; i++) {
        int num = map[domain[i]];

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