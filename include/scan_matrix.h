#ifndef SCANMATRIX_H
#define SCANMATRIX_H

typedef struct {
    int rows;
    int columns;
    int **matrix;
} ScanMatrix;

ScanMatrix *scanner_init(char* file_name);

#endif