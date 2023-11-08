/* This file defines the initialization of the reporting module.
This module supposedly prepares a text file :user_given_file_scan_report.txt; replacing user_given_file with the name of the file that the user wants to scan.
The title of the txt file is "Report on vulnerability risk scan"
Then for each vulnerability scan specified by the user, the report makes a paragraph that is organised as follows:
Vulnerability : The name of the vulnerability
Potential vulnerable lines: list of vulnerable lines detected by the scanner

To do this we need to give the scanner a pointer to an array pr vulnerability that will be filled by 
the potentially vulnerable lines and later used to fill the above mentioned text file*/

/*After the tests, the possible vulnerabilities are listed along with some links to good practices
to avoid such vulnerabilities.*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include "scanner.h"
#include "scan_matrix.h"


int init_reporting(char *file_name, ScanMatrix *scanmatrix){

    printf("Initializing the report file...\n");
    FILE *report_fp;
    // open the file in write mode and name it after the file that the user wants to scan + _scan_report.txt
    char *report_file_name = strcat(file_name, "_scan_report.txt");
    report_fp = fopen(report_file_name, "w+");

    if (report_fp == NULL)
        exit(EXIT_FAILURE);

    // Write the Title of the report
    fprintf(report_fp,"**Report on vulnerability risk scan**\n\n");
    fprintf(report_fp,"*Brought to you by: so-w-on*\n\n\n");
    
    fprintf(report_fp,"\n\n*Command injection risk report*\n");

    int count_c = 0;
    for (int i = 0; i<scanmatrix->rows; i++)
    {
        if (scanmatrix->matrix[0][i] == 1)
        {
            fprintf(report_fp,"Line %d is vulnerable to command injection risk\n", i);
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
        fprintf(report_fp,"https://owasp.org/www-community/attacks/Command_Injection\n");            
    }
    
    fprintf(report_fp,"\n\n*Buffer overflow risk report*\n");
    int count_b = 0;
    for (int i = 0; i<scanmatrix->rows; i++)
    {
        if (scanmatrix->matrix[1][i] == 1)
        {
            fprintf(report_fp,"Line %d is vulnerable to buffer overflow risk\n", i);
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
        fprintf(report_fp,"https://owasp.org/www-community/vulnerabilities/Buffer_Overflow\n");            
    }

    fprintf(report_fp,"\n\n*Memory corruption risk report*\n");
    int count_m = 0;
    for (int i = 0; i<scanmatrix->rows; i++)
    {
        if (scanmatrix->matrix[2][i]== 1)
        {
            fprintf(report_fp,"Line %d is vulnerable to memory corruption risk\n", i);

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
        fprintf(report_fp,"Links to good practices to avoid memory corruption risk:\n");
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