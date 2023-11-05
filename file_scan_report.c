/* This file defines the initialization of the reporting module.
This module supposedly prepares a text file :user_given_file_scan_report.txt; replacing user_given_file with the name of the file that the user wants to scan.
The title of the txt file is "Report on vulnerability risk scan"
Then for each vulnerability scan specified by the user, the report makes a paragraph that is organised as follows:
Vulnerability : The name of the vulnerability
Potential vulnerable lines: list of vulnerable lines detected by the scanner

To do this we need to give the scanner a pointer to an array pr vulnerability that will be filled by 
the potentially vulnerable lines and later used to fill the above mentioned text file*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include "scanner.h"
#include "file_scan_report.h"

int init_reporting(char *file_name){

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

    

    fclose(report_fp);
}