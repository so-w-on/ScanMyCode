#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include "scan_matrix.h"

//This is the first function that initializes the scanner,
//defines the list of pre-defined strings that indicate a potential vulnerability
//opens the file, and reads through it, scanning line by line.

ScanMatrix *scanner_init(char* file_name);

/* This function checks for the existance of each pre-defined string vulnerable to command injections*/
int command_injection_check(char *line, char *command_injection_strings[], int n_cmd_injections);

/* This function checks for the existance of each pre-defined string vulnerable to buffer overflows*/
int buffer_overflow_check(char *line, char *buffer_overflow_strings[], int n_buffer_overflows);

/* This function checks for the existance of each pre-defined string vulnerable to memory corruptions*/
int memory_corruption_check(char *line, char* memory_corruption_strings[], int n_memory_corruption);
