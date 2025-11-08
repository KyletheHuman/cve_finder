#ifndef DATA_PROCESSOR_H
#define DATA_PROCESSOR_H
#include <iostream>
#include <string>
#include <vector>
#include "cve_struct.h"
using namespace std;

vector<CVEstruct> loadData();
void updateData();
bool downloadFile(const string &url, const string &outPath);
bool decompressFile(const string &gzipPath, const string &outPath);
vector<CVEstruct*> parseJson(const string &jsonPath);
void saveData(const vector<CVEstruct> &cves, const string &outPath);

#endif
