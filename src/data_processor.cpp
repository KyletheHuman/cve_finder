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
    // updateData();
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
    cveEntry.vendor = cveJson.value("vendor", "any");
    cveEntry.product = cveJson.value("product", "none");
    cveEntry.version = cveJson.value("version", "any");
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


vector<CVEstruct> parseJson(const string &jsonPath) { //individual json files
  // vector<CVEstruct> cves;
  // ifstream jsonFile(jsonPath);

  // json data;
  // jsonFile >> data;
  // jsonFile.close();

  // for (auto &cveJson : data["CVE_Items"]) {
  //   CVEstruct cve;
  //   cve.id = cveJson["cve"]["CVE_data_meta"].value("ID", "temp");
    
  //   if (cveJson["cve"]["description"].contains("description_data")) {
  //     for (auto &description : cveJson["cve"]["description"]["description_data"]) {
  //       if (description.value("lang", "") == "en") {
  //         cve.description = description.value("value", "temp");
  //         break;
  //       }
  //     }
  //   }
    
  //   if (cveJson.contains("impact") && cveJson["impact"].contains("baseMetricV3")) {
  //     cve.cvss3score = cveJson["impact"]["baseMetricV3"]["cvssV3"].value("baseScore", -1.0);
  //   } else {
  //     cve.cvss3score = -1.0; 
  //   }

  //   cve.vendor = "";
  //   cve.product = "";
  //   cve.version = "";

  //   //nvd stores software under configurations -> nodes -> cpe_match as cpe:2.3:a:microsoft:minecraft:1.7.2:*:*...
  //   if (cveJson.contains("configurations") && cveJson["configurations"].contains("nodes")) {
  //     for (const auto &node : cveJson["configurations"]["nodes"]) {
  //       if (node.contains("cpe_match")) {
  //         for (const auto &cpe : node["cpe_match"]) {
  //           if (cpe.contains("cpe23Uri")) {
              
  //             string cpeEntry = cpe["cpe23Uri"];
  //             vector<string> cpeFields;
  //             string temp;
  //             for (char letter : cpeEntry) {
  //               if (letter == ':') {
  //                 cpeFields.push_back(temp);
  //                 temp.clear();
  //               } else {
  //                 temp += letter;
  //               }
  //             }
              
  //             cpeFields.push_back(temp);
  //             if (cpeFields.size() >= 6) { //makes sure has all fields
  //               cve.vendor = cleanInput(cpeFields[3]);
  //               cve.product = cleanInput(cpeFields[4]);
  //               cve.version = cleanInput(cpeFields[5]);
  //               if (cve.vendor == "*" || cve.vendor == "-") {
  //                 cve.vendor = "";
  //               }
  //               if (cve.version == "*" || cve.version == "-") {
  //                 cve.version = "";
  //               }
  //             }
  //             break;
  //           }
  //         }
  //       }
  //     }
  //   }
  //   cves.push_back(cve);
  // }
  // cout << "Parsed: Complete " << jsonPath << endl;
  // return cves;
   vector<CVEstruct> cves;
    ifstream jsonFile(jsonPath);
    json data;
    jsonFile >> data;
    jsonFile.close();

    if (!data.contains("vulnerabilities")) return cves;

    for (auto &vuln : data["vulnerabilities"]) {
        CVEstruct cve;
        if (vuln.contains("cve")) {
            auto &cveJson = vuln["cve"];
            cve.id = cveJson["id"].get<string>();
            if (cveJson.contains("descriptions")) {
                for (auto &desc : cveJson["descriptions"]) {
                    if (desc.value("lang", "") == "en") {
                        cve.description = desc.value("value", "");
                        break;
                    }
                }
            }
        }

        // You can add CVSS parsing and vendor/product logic here
        cves.push_back(cve);
    }

    cout << "Parsed: Complete " << jsonPath << " (" << cves.size() << " CVEs)" << endl;
    return cves;
}


void saveData(const vector<CVEstruct> &cves, const string &outPath) {
  json combinedJson;
  for (const auto &cve : cves) {
    combinedJson.push_back({
      {"id", cve.id},
      {"description", cve.description},
      {"cvss3score", cve.cvss3score},
      {"vendor", cve.vendor},
      {"product", cve.product},
      {"version", cve.version}
      });
  }

  ofstream outFile(outPath);
  outFile << combinedJson.dump(4); //dumps and makes readable
  outFile.close();
  cout << "Data Saving: Complete" << endl;
}


void updateData() {
  // // filesystem::create_directories("data");
  // vector<CVEstruct> cves;

  // curl_global_init(CURL_GLOBAL_DEFAULT);
  
  // for (int year = 2010; year < 2026; ++year) {
  //   string url = "https://services.nvd.nist.gov/rest/json/cves/2.0?"
  //            "kevStartDate=2010-01-01T00:00:00Z&"
  //            "kevEndDate=2025-11-01T23:59:59Z";
  //   string gzipPath = "data/nvdcve-1.1-" + to_string(year) + ".json.gz"; //local file path
  //   string jsonPath = "data/nvdcve-1.1-" + to_string(year) + ".json";    //local file path

  //   downloadFile(url, gzipPath);
  //   // decompressFile(gzipPath, jsonPath);
  //   vector<CVEstruct> cvesEachYear = parseJson(jsonPath);
  //   cves.insert(cves.end(), cvesEachYear.begin(), cvesEachYear.end());
  // }

  // saveData(cves, "data/cve_data.json");
  // curl_global_cleanup();
  // cout << "Update completed. CVE data points gathered: " << cves.size() << endl;
  vector<CVEstruct> allCves;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    // --- Example: KEV API download ---
    // string url = "https://services.nvd.nist.gov/rest/json/cves/2.0?"
    //              "kevStartDate=2010-01-01T00:00:00Z&kevEndDate=2025-11-01T23:59:59Z";
    // string outPath = "data/kev_cves.json";

    // if (downloadFile(url, outPath)) {
    //     vector<CVEstruct> cves = parseJson(outPath);
    //     allCves.insert(allCves.end(), cves.begin(), cves.end());
    // }

    // --- Optional: yearly .json.gz feed ---
    for (int year = 2010; year <= 2025; ++year) {
        // // string gzipUrl = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-" + to_string(year) + ".json.gz";
        // // string gzipPath = "data/nvdcve-1.1-" + to_string(year) + ".json.gz";
        // string jsonPath = "data/nvdcve-2.0-" + to_string(year) + ".json";

        // // if (!downloadFile(gzipUrl, gzipPath)) continue;
        // // if (!decompressFile(gzipPath, gzipPath)) continue;

        // vector<CVEstruct> yearCves = parseJson(jsonPath);
        // cout << yearCves[0].product << endl;
        // for (CVEstruct &cve : yearCves) {
        //   allCves.push_back(cve);
        // }
        // // allCves.insert(allCves.end(), yearCves.begin(), yearCves.end());
        // cout << allCves.size() << endl;
        string jsonPath = "data/nvdcve-2.0-" + to_string(year) + ".json";

      try {
          vector<CVEstruct> yearCves = parseJson(jsonPath);

          if (!yearCves.empty()) {
              cout << yearCves[0].product << endl;
          }

          for (const CVEstruct &cve : yearCves) {
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




