/* This file contains the scanner module that analyzes the file given by the user for these vulnerabilities :
Command injection, Weak or hardcoded passwords, Buffer overflow risk, Memory corruption risk,
Vulnerable third-party libraries, Race conditions, Concurrency issues
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

// Function to initialize scanner
int scanner_init(char* file_name)
{
    printf("Initializing scanner...\n");
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    size_t read;

    // Define one array that contains all the patterns to be searched for in the file for command injection risk
    char *command_injection_strings[]= {"system(", "popen(", "exec(", "execve(", "execl(", "execlp(", "execle(", "execv(", "execvp(", "execvpe(", "system (", "popen (", "exec (", "execve (", "execl (", "execlp (", "execle (", "execv (", "execvp (", "execvpe (", "system\t(", "popen\t(", "exec\t(", "execve\t(", "execl\t(", "execlp\t(", "execle\t(", "execv\t(", "execvp\t(", "execvpe\t(", "system\t (", "popen\t (", "exec\t (", "execve\t (", "execl\t (", "execlp\t (", "execle\t (", "execv\t (", "execvp\t (", "execvpe\t ("};
    // Define one array that contains all the patterns to be searched for in the file for buffer overflow risk
    char *buffer_overflow_strings[]= {"gets(", "strcpy(", "strcat(", "sprintf(", "vsprintf(", "gets (", "strcpy (", "strcat (", "sprintf (", "vsprintf (", "gets\t(", "strcpy\t(", "strcat\t(", "sprintf\t(", "vsprintf\t(", "gets\t (", "strcpy\t (", "strcat\t (", "sprintf\t (", "vsprintf\t ("};
    // Define one array that contains all the patterns to be searched for in the file for memory corruption risk
    char *memory_corruption_strings[]= {"memcpy(", "memmove(", "memset(", "memcpy (", "memmove (", "memset (", "memcpy\t(", "memmove\t(", "memset\t(", "memcpy\t (", "memmove\t (", "memset\t ("};
    // TODO: create a database file that contains these predefined strings etc and load from it.

    fp = fopen(file_name, "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    //use the other functions
    while((read = getline(&line, &len, fp)) != -1){
        command_injection_check(line, command_injection_strings);
        buffer_overflow_check(line, buffer_overflow_strings);
        memory_corruption_check(line, memory_corruption_strings);
    }

    fclose(fp);
    if (line)
        free(line);
    return 0;
}

// Function to check for command injection risk
int command_injection_check(char *line, char *command_injection_strings[])
{
    int n_cmd_injections = len(command_injection_strings);
    for (int i = 0; i < n_cmd_injections; i++){
        if (strstr(line, command_injection_strings[i]) != NULL){
            printf("Command injection risk detected in the file.\n");
            return 1;
        }
    }
    return 0;
}

// Function to check for buffer overflow risk
int buffer_overflow_check(char *line, char *buffer_overflow_strings[])
{
    int n_buffer_overflows = len(buffer_overflow_strings);
    for (int i = 0; i < n_buffer_overflows; i++){
        if (strstr(line, buffer_overflow_strings[i]) != NULL){
            printf("Buffer overflow risk detected in the file.\n");
            return 1;
        }
    }
    return 0;
}

// Function to check for memory corruption risk
int memory_corruption_check(char *line, char* memory_corruption_strings[])
{
    int n_memory_corruption = len(memory_corruption_check);
    for (int i = 0; i < n_memory_corruption; i++){
        if (strstr(line, memory_corruption_strings[i]) != NULL){
            printf("Memory corruption risk detected in the file.\n");
            return 1;
        }
    }
    return 0;
}

