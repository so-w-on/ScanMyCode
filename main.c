/*This is the main file. The user will run this program like this ./ScanMyCode -bmc filetoscan
b is to check for buffer overflow risk using the function from scanner.c
m is to check for memory corruption risk using the function from scanner.c
c is to check for command injection using the function from scanner.c
filetoscan is the file that the user wants to scan for the risks
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
//TODO : find a fix for not being able to run getopt.h and maybe similar Unix-only available libraries on Windows
#include <getopt.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include "scanner.h"
#include "file_scan_report.h"

int main(int argc, char *argv[]) {
    int option;
    int c_flag = 0; // Flag to indicate the -c option
    int b_flag = 0; // Flag to indicate the -b option
    int m_flag = 0; // Flag to indicate the -m option

    while ((option = getopt(argc, argv, "cbm")) != -1) {
        switch (option) {
            case 't':
                c_flag = 1;
                break;
            case 'b':
                b_flag = 1;
                break;
            case 'v':
                m_flag = 1;
                break;
            case '?':
                // Handle invalid options or missing arguments
                fprintf(stderr, "Usage: %s [-c] [-b] [-m] filetoscan\n", argv[0]);
                exit(EXIT_FAILURE);
            default:
                // Handle other options if needed
                break;
        }
    }

    // Check for the required file name after processing options
    if (optind >= argc) {
        fprintf(stderr, "Missing file name.\n");
        exit(EXIT_FAILURE);
    }

    char *file_name = argv[optind]; // The file name to scan



    if (c_flag == 1) {
        printf("Checking for command injection risk...\n");
        command_injection_check(file_name);
    }
    if (b_flag == 1) {
        printf("Checking for buffer overflow risk...\n");
        buffer_overflow_check(file_name);
    }
    if (m_flag == 1) {
        printf("Checking for memory corruption risk...\n");
        memory_corruption_check(file_name);
    }

    return 0;
}


