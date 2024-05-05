#include "header.h"

int debug_mode = NO_DEBUG;
char server_ip[16] = DEFAULT_ADDRESS;
char config_path[100] = DEFAULT_PATH;
const int port = 53;

static void print_info() {
    const char date[] = __DATE__;
    const char time[] = __TIME__;

    printf("SourceCode at https://github.com/wangquanlikun/DNS_Relay. Fork and Star\n");
    printf("DNSRELAY, Version %s, Build: %s %s\n", VERSION, date, time);
    printf("Usage: dnsrelay [-d | -dd] [<dns-server>] [<db-file>]\n\n");
    
    printf("Name server: %s:%d.\n", server_ip, port);
    printf("Debug level %d.\n", debug_mode);

    printf("Bind UDP port %d ...", port);
    if(bind_port())
        printf("OK.\n");
    else {
        printf("Failed.\n");
        exit(1);
    }

    printf("Try to load table \"%s\" ...", config_path);
    if(load_config())
        printf("OK.\n");
    else{
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

int load_config() {
    return 0;
}