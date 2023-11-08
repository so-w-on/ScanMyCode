/* This file contains the scanner module that analyzes the file given by the user for these vulnerabilities :
Command injection, Weak or hardcoded passwords, Buffer overflow risk, Memory corruption risk,
Vulnerable third-party libraries, Race conditions, Concurrency issues
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <sys/types.h>
#include "file_scan_report.h"
#include "scan_matrix.h"

// Function to initialize scanner
//scanner_init will return a matrix that will be passed to the reporting module
// The matrix will be filled with 1s and 0s depending on the presence of the vulnerability in the file
// The matrix will be of size 3xN where N is the number of lines in the file
// The first row will be for command injection risk
// The second row will be for buffer overflow risk
// The third row will be for memory corruption risk

ScanMatrix *scanner_init(char *file_name)
{
    printf("Initializing scanner...\n");
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    int line_number = 0;
    ScanMatrix *scanmatrix;
    int rows = 0;   
    int columns = 3; 
    char ch;

    // Define one array that contains all the patterns to be searched for in the file for command injection risk
    char *command_injection_strings[]= {"system", "popen", "exec", "execve", "execl", "execlp", "execle", "execv", "execvp", "execvpe", "eval", "call", "shell_exec", "proc_open", "ShellExecute"};
    int n_cmd_injections = sizeof(command_injection_strings) / sizeof(command_injection_strings[0]);

    // Define one array that contains all the patterns to be searched for in the file for buffer overflow risk
    // This array contains strings that are 
    char *buffer_overflow_strings[]= {"gets", "scanf", "strcpy", "strcat", "sprintf", "vsprintf","snprintf", "syslog"};
    int n_buffer_overflows = sizeof(buffer_overflow_strings) / sizeof(buffer_overflow_strings[0]);

    // Define one array that contains all the patterns to be searched for in the file for memory corruption risk
    char *memory_corruption_strings[]= {"memcpy", "memmove", "memset"};
    int n_memory_corruption = sizeof(memory_corruption_strings) / sizeof(memory_corruption_strings[0]);

    /*
    // Define one array that contains all the patterns to search for in the file for race conditions issues
    char *race_conditions_strings[]= {"access", "chown", "chgrp", "chmod", "tmpfile", "tmpnam", "tempnam", "mktemp"};
    */

    // TODO: create a database file that contains these predefined strings etc and load from it.

    fp = fopen(file_name, "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    // Count number of lines in file
    while ((ch = fgetc(fp)) != EOF) {
        if (ch == '\n') {
            rows++;
        }
    }
    printf("Initializing matrix...\n");
    // init Scanmatrix
    scanmatrix = (ScanMatrix *)malloc(sizeof(ScanMatrix));
    if (scanmatrix == NULL) 
    {
        perror("Memory allocation for ScanMatrix failed.");
    } else 
    {
        initializeMatrix(scanmatrix, rows, columns);
    }
    printf("Done Initializing matrix...\n");
    
    rewind(fp);
    //use the other functions
    while((read = getline(&line, &len, fp)) != -1){
        scanmatrix->matrix[0][line_number] = command_injection_check(line, command_injection_strings, n_cmd_injections);
        scanmatrix->matrix[1][line_number] = buffer_overflow_check(line, buffer_overflow_strings, n_buffer_overflows);
        scanmatrix->matrix[2][line_number] = memory_corruption_check(line, memory_corruption_strings, n_memory_corruption);
        line_number++;
    }

    fclose(fp);
    printf("file closed\n");
    if (line)
        free(line);
    return scanmatrix;
}

// Function to check for command injection risk
int command_injection_check(char *line, char *command_injection_strings[], int n_cmd_injections)
{
    for (int i = 0; i < n_cmd_injections; i++){
        if (strstr(line, command_injection_strings[i]) != NULL){
            // printf("Command injection risk detected in this line.\n");
            return 1;
        }
    }
    return 0;
}

// Function to check for buffer overflow risk
// It goes through the file looking for function that may be exploited by the user if not proper measures are taken into account.
// These functions are the one known to be vulnerable to the following: Stack or Heap overflow and format strings.
int buffer_overflow_check(char *line, char *buffer_overflow_strings[], int n_buffer_overflows)
{
    for (int i = 0; i < n_buffer_overflows; i++){
        if (strstr(line, buffer_overflow_strings[i]) != NULL){
            // printf("Buffer overflow risk detected in the file.\n");
            return 1;
        }
    }
    return 0;
}

// Function to check for memory corruption risk
int memory_corruption_check(char *line, char* memory_corruption_strings[], int n_memory_corruption)
{
    for (int i = 0; i < n_memory_corruption; i++){
        if (strstr(line, memory_corruption_strings[i]) != NULL){
            // printf("Memory corruption risk detected in the file.\n");
            return 1;
        }
    }
    return 0;
}

void initializeMatrix(ScanMatrix *scanmatrix, int rows, int columns)
{
    scanmatrix->rows = rows;
    scanmatrix->columns = columns;
    scanmatrix->matrix = (int **)malloc(columns * sizeof(int *));
    for (int i = 0; i < columns; i++)
        scanmatrix->matrix[i] = (int *)malloc(rows * sizeof(int));
}