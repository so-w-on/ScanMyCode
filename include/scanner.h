#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include "scan_matrix.h"

ScanMatrix *scanner_init(char* file_name);

int command_injection_check(char *line, char *command_injection_strings[], int n_cmd_injections);

int buffer_overflow_check(char *line, char *buffer_overflow_strings[], int n_buffer_overflows);

int memory_corruption_check(char *line, char* memory_corruption_strings[], int n_memory_corruption);
