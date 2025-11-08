#include <iostream>
// #include <filesystem>
#include <fstream>
#include <curl/curl.h>
#include <vector>
#include <zlib.h>
#include "file_checker.h"
#include "data_processor.h"
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
  string dataPath = "data/cve_data.json";
  if (!checkFile(dataPath)) {
    cout << "No current CVE data, updating..." << endl;
    updateData();
  }

  if (!checkFile(dataPath)) {
    cout << "Error: No current CVE data" << endl;
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
    cveEntry.cvssVector = cveJson.value("cvssVector", "temp");
    cveEntry.vendor = cveJson.value("vendor", "any");
    cveEntry.product = cveJson.value("product", "none");
    cveEntry.version = cveJson.value("version", "any");
    cves.push_back(cveEntry);
  }
  
  cout << "Loaded " << cves.size() << " CVE data points" << endl;
  return cves;
}

size_t curlDataHandler(void* contents, size_t size, size_t bytes, void* outputFilePtr) {
  FILE* localFile = (FILE*)outputFilePtr;
  return fwrite(contents, size, bytes, localFile);
}

bool downloadFile(const string &url, const string &outPath) {
  CURL* curl = curl_easy_init(); 
  if (!curl) {
    cout << "Error: curl init failed" << endl;
    return false;
  }
  FILE* localFile = fopen(outPath.c_str(), "wb");     //opens local file in inary mode (wb) to out into
  if (!localFile) {
        cout << "Error: cannot open local file\n";
        curl_easy_cleanup(curl);
        return false;
    }
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());  //download url
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlDataHandler); //tells how to handle incoming data chunks
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, localFile); //sends data to open local file
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); //allows for redirects on page

   curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
   curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

   curl_easy_setopt(curl, CURLOPT_USERAGENT, 
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36");


  CURLcode curlResponse = curl_easy_perform(curl); //connnects to server and downloads
  fclose(localFile);
  curl_easy_cleanup(curl);
  if (curlResponse != CURLE_OK) {
        cout << "CURL error: " << curl_easy_strerror(curlResponse) << endl;
        return false;
    }

  // Check if file is empty
  ifstream f(outPath, ios::binary | ios::ate);
  if (!f.is_open() || f.tellg() == 0) {
      cerr << "Downloaded file is empty: " << outPath << endl;
      return false;
  }

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


vector<CVEstruct*> parseJson(const string &jsonPath) { //individual json files
   vector<CVEstruct*> cves;
    ifstream jsonFile(jsonPath);
    json data;
    jsonFile >> data;
    jsonFile.close();

  if (!data.contains("vulnerabilities")) return cves;

  for (auto &vuln : data["vulnerabilities"]) {
    if (!vuln.contains("cve")) continue;

    auto &cveJson = vuln["cve"];

    // shared CVE metadata
    string id = cveJson.value("id", "");
    string description = "";
    double cvssScore = 0.0;
    string cvssVector = "";

    // description
    if (cveJson.contains("descriptions")) {
        for (auto &desc : cveJson["descriptions"]) {
            if (desc.value("lang", "") == "en") {
                description = desc.value("value", "");
                break;
            }
        }
    }
    
    if (cveJson.contains("metrics")) {
      auto& metrics = cveJson["metrics"];
      //CVSS 2.0
      if (metrics.contains("cvssMetricV2")) {
          auto &cvssList = metrics["cvssMetricV2"];
          if (!cvssList.empty() && cvssList[0].contains("cvssData")) {
              auto &cvssData = cvssList[0]["cvssData"];
              cvssVector = cvssData.value("vectorString", "");
              cvssScore  = cvssData.value("baseScore", 0.0);
          }
      }
      // CVSS 3.1
      if (metrics.contains("cvssMetricV31")) {
          auto &cvssList = metrics["cvssMetricV31"];
          if (!cvssList.empty() && cvssList[0].contains("cvssData")) {
              auto &cvssData = cvssList[0]["cvssData"];
              cvssVector = cvssData.value("vectorString", "");
              cvssScore  = cvssData.value("baseScore", 0.0);
          }
      }
    }

    // Now parse configurations
    if (!cveJson.contains("configurations")) continue;

    auto &configs = cveJson["configurations"];

    for (auto &config : configs) {
        if (!config.contains("nodes")) continue;

        for (auto &node : config["nodes"]) {
            if (!node.contains("cpeMatch")) continue;

            for (auto &cpeMatch : node["cpeMatch"]) {
                if (!cpeMatch.contains("criteria")) continue;

                string fullCPE = cpeMatch["criteria"];

                // Parse cpe:2.3:part:vendor:product:version:
                vector<string> fields;
                {
                    string temp;
                    stringstream ss(fullCPE);
                    while (getline(ss, temp, ':')) {
                        fields.push_back(temp);
                    }
                }
                if (fields.size() < 6) continue;

                string vendor  = fields[3];
                string product = fields[4];
                string version = fields[5];

                // Create cve for each one associated with cpe
                CVEstruct* cve = new CVEstruct();
                cve->id = id;
                cve->description = description;
                cve->vendor = vendor;
                cve->product = product;
                cve->version = version;
                cve->cvss3score = cvssScore;
                cve->cvssVector = cvssVector;

                cves.push_back(cve);
            }
        }
    }
  }

  cout << "Parsed: Complete " << jsonPath << " (" << cves.size() << " CVEs)" << endl;
  return cves;
}


void saveData(const vector<CVEstruct*> &cves, const string &outPath) {
  json combinedJson;
  for (const auto &cve : cves) {
    combinedJson.push_back({
      {"id", cve->id},
      {"description", cve->description},
      {"cvss3score", cve->cvss3score},
      {"cvssVector", cve->cvssVector},
      {"vendor", cve->vendor},
      {"product", cve->product},
      {"version", cve->version}
      });
  }

  ofstream outFile(outPath);
  outFile << combinedJson.dump(4); //dumps and makes readable
  outFile.close();
  cout << "Data Saving: Complete" << endl;
}


void updateData() {
  vector<CVEstruct*> allCves;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    for (int year = 2010; year <= 2025; ++year) {
      string jsonPath = "data/nvdcve-2.0-" + to_string(year) + ".json";

      //we got a lot of errors at this part
      try {
          vector<CVEstruct*> yearCves = parseJson(jsonPath);

          for (CVEstruct* cve : yearCves) {
              allCves.push_back(cve);
          }

          cout << "Total CVEs so far: " << allCves.size() << endl;

      } catch (const std::exception &e) {
          cerr << "Error parsing " << jsonPath << ": " << e.what() << endl;
          continue;  // skip to next year
      }
    }

    curl_global_cleanup();

    saveData(allCves, "data/cve_data.json");
    cout << "Update completed. Total CVEs: " << allCves.size() << endl;
}




