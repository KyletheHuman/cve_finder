#include <iostream>
#include <filesystem>
#include <curl/curl.h>
#include <zlib.h>
#include <file_checker.h>
using namespace std;

//cURL writing to file
//load data if it is already saved
//update data
  //download
  //decompress
  //parse
  //save
vector<CVEstruct> loadData();
void updateData();
bool downloadFile(const string &url, const string &outPath);
bool decompressFile(const string &gzipPath, const string &outPath);
vector<CVEstruct> parseJson(const string &jsonPath);
void saveData(const vector<CVEstruct> &cves, const string &outPath);



