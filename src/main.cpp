#include "cve_struct.h"
#include "data_processor.h"
#include "file_checker.h"
#include "trie.h"
#include "RedBlackTree.h"

#include <chrono>
#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <cctype>
using namespace std;


bool checkMatch(const string &fromData, const string &fromSearch) {
  if (fromSearch == "") {
    return true;
  }
  if (fromData == "") {
    return true;
  }
  return fromSearch == fromData;
}

void printCVE(const CVEstruct &cve, const string &vendorInput, const string &versionInput) {
    cout << "--------------------" << endl;
    cout << "ID:  " << cve.id << endl;
    if (vendorInput.empty()) {
        cout << "Vendor:  ";
        if (!cve.vendor.empty())
            cout << cve.vendor << endl;
        else
            cout << "any" << endl;
    }
    if (versionInput.empty()) {
        cout << "Version:  ";
        if (!cve.version.empty())
            cout << cve.version << endl;
        else
            cout << "any" << endl;
    }

    cout << "CVSS3 Score:  " << cve.cvss3score << endl;
    cout << "Description:  ";
    if (cve.description.size() > 200) { //shortens
        cout << cve.description.substr(0, 200) << "..." << endl;
    } else {
        cout << cve.description << endl;
    }
}

string formatCPE(string vendor, string product, string version) {
    return vendor + "-" + product + "-" + version;
}

int main (int argc, char* argv[]) {
  cout << "CVE Finder" << endl;
  cout << "commands: update, load, search, exit" << endl;

  vector<CVEstruct> cves; //stores all cves
  string command;

  Trie trie;
  RedBlackTree RBT;
  //Tree tree;

  unordered_map<int, CVEStruct*> RBTIndex;


  while(true) {
    getline(cin, command);
    command = cleanInput(command);
    
    if (command == "exit") {
      break;
      
    } else if (command == "update") {
      cout << "Updating CVE data" << endl;
      updateData();
      
    } else if (command == "load") {
      cout << "Loading CVE data" << endl;
      cves = loadData();
      if (cves.empty()) {
        cout << "No local data. Try update" << endl;
      }

      cout << "Building Trie" << endl;
      for (auto &cve :cves) {
        if (!cve.product.empty()) {
          string cpe = cve.cpe();
          trie.insert(cpe, &cve);
        }
      }
      cout << "Trie built" << endl;

      cout << "Building Red-Black Tree" << endl;
      // Clear previous tree/index
      rbt.clear();
      rbtIndex.clear();

      // Insert CVEs into the RBT and fill the side index
      for (auto &cve : cves) {
        if (cve.id.empty()) continue;

        // Parse CVE-YYYY-NNNNNN inline (no helpers)
        string t; t.reserve(cve.id.size());
        for (unsigned char ch : cve.id) t.push_back(std::toupper(ch));
        if (t.rfind("CVE-", 0) != 0) continue;
        size_t dash2 = t.find('-', 4);
        if (dash2 == string::npos) continue;

        int year = 0, num = 0;
        try {
          year = stoi(t.substr(4, dash2 - 4));
          num  = stoi(t.substr(dash2 + 1));
        } catch (...) { continue; }
        if (num < 0 || num > 999999) continue;

        int key = year * 1'000'000 + num;
        rbt.insert(key);
        rbtIndex[key] = &cve;
      }
      
      cout << "Red-Black Tree built" << endl;

      cout << "CVEs:  " << cves.size() << endl;
      
    } else if (command == "search") {
      if (cves.empty()) {
        cout << "No local data. Try load or update" << endl;
        continue;
      }
      
      string vendor;
      string product;
      string version;
      
      cout << "Search - leave fields vendor and/or version blank to search for all" << endl;
      cout << "Note: do not leave product blank" << endl;
      cout << "Enter vendor:  ";
      getline(cin, vendor);
      vendor = cleanInput(vendor);
      
      cout << "Enter product*:  ";
      getline(cin, product);
      if (product.empty()) {
        while(product.empty()) {
          cout << "Error: product can not be left empty" << endl;
          cout << "Enter product*:  ";
          getline(cin, product);
        }
      }
      product = cleanInput(product);
      
      cout << "Enter version:  ";
      getline(cin, version);
      version = cleanInput(version);

      cout << "Searching CVEs" << endl;
      int count = 0;
      //base search for now
      // for (const auto &cve : cves) {
      //   // if (checkMatch(cve.product, product) && checkMatch(cve.vendor, vendor) && checkMatch(cve.version, version)) {
      //   //   printCVE(cve, vendor, version);
      //   //   count++;
      //   // }
      // }

      string cpe = formatCPE(vendor, product, version);
      CPEData* result = trie.search(cpe);
      if (result == nullptr) {
                    cout << "CPE not found." << endl;
                    continue;
                }
                for (CVEstruct* cve : result->cves) {
                    cve->print();
                }
            int foundInRBT = 0;

      for (CVEstruct* cve : result->cves) {
        if (!cve || cve->id.empty()) continue;

        string t; t.reserve(cve->id.size());
        for (unsigned char ch : cve->id) t.push_back(std::toupper(ch));
        if (t.rfind("CVE-", 0) != 0) continue;
        size_t dash2 = t.find('-', 4);
        if (dash2 == string::npos) continue;

        int year = 0, num = 0;
        try {
          year = stoi(t.substr(4, dash2 - 4));
          num  = stoi(t.substr(dash2 + 1));
        } catch (...) { continue; }
        if (num < 0 || num > 999999) continue;

        int key = year * 1'000'000 + num;

        Node* hit = rbt.search(key);
        if (hit != rbt.getNIL()) {
          auto it = rbtIndex.find(key);
          if (it == rbtIndex.end() || it->second == cve)
            foundInRBT++;
        }  
    }
      
      auto startTimeTrie = chrono::high_resolution_clock::now();
      //insert into trie
      auto endTimeTrie = chrono::high_resolution_clock::now();
      auto durationTrie = chrono::duration_cast<chrono::milliseconds>(endTimeTrie - startTimeTrie).count();

      auto startTimeRB = chrono::high_resolution_clock::now();
      //insert into red-black
      auto endTimeRB = chrono::high_resolution_clock::now();
      auto durationRB = chrono::duration_cast<chrono::milliseconds>(endTimeRB - startTimeRB).count();  

      if (count == 0) {
        cout << "No matching CVEs found" << endl;
      } else {
        cout << "CVEs found:  " << count << endl;
      }
      
    } else {
      cout << "No command found" << endl;
    }
  }

  // cout to user how to format search
  
  //searches and printing out

  //time tree searches
  return 0;
}
