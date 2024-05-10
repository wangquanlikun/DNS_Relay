#include "header.h"

int main(int argc, char* argv[]) {
    set_parameter(argc, argv);
    init_data();

    run_server();
    return 0;
}