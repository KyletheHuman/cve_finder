#include <iostream>
#include <filesystem>
#include <fstream>
#include <curl/curl.h>
#include <zlib.h>
#include "file_checker.h"
#include "api_processor.h"
#include "nlohmann/json.hpp"
using json = nlohmann::json;
using namespace std;

//cURL writing to file
//load data if it is already saved
//update data
  //download
  //decompress
  //parse
  //save
vector<CVEstruct> loadData() {
  vector<CVEstruct> cves;
  string dataPath = "data/cves_data.json";
  if (!checkFile(dataPath)) {
    cout << "No current CVE data, please update" << endl;
    return cves;
  }

  ifstream dataFile(dataPath);
  json inputs;
  dataFile >> inputs;
  dataFile.close();

  for (auto &cveJson : inputs) {
    CVEstruct cveEntry;
    cveEntry.id = cveJson.value("id", "temp");
    cveEntry.description = cveJson.value("description", "temp");
    cveEntry.cvss3score = cveJson.value("cvss3score", -1.0);
    cveEntry.productversion = cveJson.value("productversion", "temp");
    cves.push_back(cveEntry);
  }

  cout << "Loaded" << cves.size() << "CVE data points" << endl;
  return cves;
}

size_t curlDataHandler(void* contents, size_t size, size_t bytes, void* outputFilePtr) {
  FILE* localFile = (FILE*)outputFilePtr;
  return fwrite(contents, size, bytes, localFile);
}

bool downloadFile(const string &url, const string &outPath) {
  CURL* curl = curl_easy_init();               //starts libcurl
  FILE* localFile = fopen(outPath.c_str(), "wb");     //opens local file in inary mode (wb) to out into

  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());  //download url
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlDataHandler); //tells how to handle incoming data chunks
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, localFile); //sends data to open local file
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); //allows for redirects on page

  CURLcode curlResponse = curl_easy_perform(curl); //connnects to server and downloads
  fclose(localFile);
  curl_easy_cleanup(curl);
  cout << "Downloaded: " << url << endl;
  return true;
}

bool decompressFile(const string &gzipPath, const string &outPath) {
  gzFile gzipFile = gzopen(gzipPath.c_str(), "rb"); //opens and reads the binary
  ofstream outFile(outPath, ios::binary); //open new file for output of decompressed data

  int readBytes = 0;
  char readBuffer[4096]; //gzread reads at 4096 bytes per cycle
  while (true) { //loops to write all decompressed data chunks to json file
    readBytes = gzread(gzipFile, readBuffer, sizeof(readBuffer));
    
    if (readBytes <= 0) {
      break;
    }
    outFile.write(readBuffer, readBytes);
  }
  
  gzclose(gzipFile);
  outFile.close();
  cout << "Decompressed gzip file" << endl;
  return true;
}
vector<CVEstruct> parseJson(const string &jsonPath);
void saveData(const vector<CVEstruct> &cves, const string &outPath);


void updateData() {
  filesystem::create_directories("data");
  vector<CVEstruct> cves;

  for (int year = 2010; year < 2026; ++year) {
    string url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-" + to_string(year) + ".json.gz"; //web download path
    string gzipPath = "data/nvdcve-1.1-" + to_string(year) + ".json.gz"; //local file path
    string jsonPath = "data/nvdcve-1.1-" + to_string(year) + ".json";    //local file path

    downloadFile(url, gzipPath);
    decompressFile(gzipPath, jsonPath);
    vector<CVEstruct> cvesEachYear = parseJson(jsonPath);
    cves.insert(cves.end(), cvesEachYear.begin(), cvesEachYear.end());
  }

  saveData(cves, "data/cve_data.json");
  cout << "Update completed. CVE data points gathered: " << cves.size() << endl;
}




