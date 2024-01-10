#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include "scanner.h"
#include "scan_matrix.h"

#define ANSI_RED     "\x1b[31m"
#define ANSI_BOLD_RED "\x1b[1;31m"
#define ANSI_RESET   "\x1b[0m"
#define ANSI_BLUE    "\x1b[34m"


int init_reporting(char *file_name, ScanMatrix *scanmatrix){
    const char* reporttitle =
    " ___                   _                         _                   _    _ _ _ _              _    _                            \n"  
    "| _ \\___ _ __  ___ _ _| |_   ___ _ _   __ ___  _| |_ _  ___ _ _ __ _| |__(_) (_) |_ _  _   _ _(_)__| |__  ___ __ __ _ _ _         \n"
    "|   / -_) '_ \\/ _ \\ '_|  _| / _ \\ ' \\  \\ V / || | | ' \\/ -_) '_/ _` | '_ \\ | | |  _| || | | '_| (_-< / / (_-</ _/ _` | ' \\        \n"
    "|_|_\\___| .__/\\___/_|  \\__| \\___/_||_|  \\_/ \\_,_|_|_||_\\___|_| \\__,_|_.__/_|_|_|\\__|\\_, | |_| |_/__/_\\_\\ /__/\\__\\__,_|_||_|       \n"
    "        |_|                                                                         |__/                                           \n\n";

    // printf("Initializing the report file...\n");
    FILE *report_fp;
    // open the file in write mode and name it after the file that the user wants to scan + _scan_report.txt
    char *report_file_name = strcat(file_name, "_scan_report.txt");
    report_fp = fopen(report_file_name, "w+");

    if (report_fp == NULL)
        exit(EXIT_FAILURE);

    fprintf(report_fp, reporttitle);
    
    fprintf(report_fp,ANSI_BOLD_RED "\n|-||-||-| Command injection risk report |-||-||-| \n\n" ANSI_RESET);

    int count_c = 0;
    for (int i = 0; i<scanmatrix->rows; i++)
    {
        if (scanmatrix->matrix[0][i] == 1)
        {
            fprintf(report_fp,ANSI_RED "Line %d " ANSI_RESET "is vulnerable to command injection risk\n", i+1);
            count_c++;
        }
    }
    if (count_c == 0)
    {
        fprintf(report_fp,"No command injection risk detected\n");
    }
    else
    {
        fprintf(report_fp,"Number of lines vulnerable to command injection risk: %d\n", count_c);
        fprintf(report_fp,"Links to good practices to avoid command injection risk:\n");
        fprintf(report_fp,ANSI_BLUE"https://owasp.org/www-community/attacks/Command_Injection\n"ANSI_RESET);            
    }
    
    fprintf(report_fp, ANSI_BOLD_RED "\n|-||-||-| Buffer overflow risk report |-||-||-| \n\n" ANSI_RESET);
    int count_b = 0;
    for (int i = 0; i<scanmatrix->rows; i++)
    {
        if (scanmatrix->matrix[1][i] == 1)
        {
            fprintf(report_fp,ANSI_RED "Line %d " ANSI_RESET "is vulnerable to buffer overflow risk\n", i+1);
            count_b++;
        }
    }
    if (count_b == 0)
    {
        fprintf(report_fp,"No buffer overflow risk detected\n");
    }
    else
    {
        fprintf(report_fp,"Number of lines vulnerable to buffer overflow risk: %d\n", count_b);
        fprintf(report_fp,"Links to good practices to avoid buffer overflow risk:\n");
        fprintf(report_fp,ANSI_BLUE"https://owasp.org/www-community/vulnerabilities/Buffer_Overflow\n"ANSI_RESET);            
    }

    fprintf(report_fp, ANSI_BOLD_RED "\n|-||-||-| Memory corruption risk report  |-||-||-| \n\n" ANSI_RESET);
    int count_m = 0;
    for (int i = 0; i<scanmatrix->rows; i++)
    {
        if (scanmatrix->matrix[2][i]== 1)
        {
            fprintf(report_fp,ANSI_RED "Line %d " ANSI_RESET "is vulnerable to memory corruption risk\n", i+1);

            count_m++;
        }
    }
    if (count_m == 0)
    {
        fprintf(report_fp,"No memory corruption risk detected\n");
    }
    else
    {
        fprintf(report_fp,"Number of lines vulnerable to memory corruption risk: %d\n", count_m);
        // fprintf(report_fp,ANSI_BLUE "Links to good practices to avoid memory corruption risk:\n"ANSI_RESET);
        fprintf(report_fp,"\n");            
    }
    freeMatrix(scanmatrix);

    fclose(report_fp);
    return 0;
}



void freeMatrix(ScanMatrix *scanmtr) {
    for (int i = 0; i < scanmtr->columns; i++) {
        free(scanmtr->matrix[i]);
    }
    free(scanmtr->matrix);
}