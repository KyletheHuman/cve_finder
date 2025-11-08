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

int main () {
  cout << "CVE Finder" << endl;
  cout << "commands: update, load, search, exit" << endl;

  vector<CVEstruct> cves; //stores all cves
  string command;

  Trie trie;
  RedBlackTree RBT;

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
        //if (!cve.product.empty()) {
          string cpe = cve.cpe();
          trie.insert(cpe, &cve);
        //}
      }
      cout << "Trie built" << endl;

      cout << "Building Red-Black Tree" << endl;
      // Clear previous tree/index
      RBT.clear();

      // Insert CVEs into the RBT and fill the side index
      for (auto &cve : cves) {
        string cpe = cve.cpe();
          RBT.insert(cpe, &cve);
      }
      
      cout << "Red-Black Tree built" << endl;

      cout << "CVEs:  " << cves.size() << endl;
      
    } else if (command == "search") {
      if (cves.empty()) {
        cout << "No local data. Try load or update" << endl;
        continue;
      }

      string mode;
      cout << "Mode (tree, trie): ";
      getline(cin, mode);
      
      string vendor;
      string product;
      string version;
      
      
      cout << "Enter vendor:  ";
      getline(cin, vendor);
      
      cout << "Enter product*:  ";
      getline(cin, product);
      if (product.empty()) {
        while(product.empty()) {
          cout << "Error: product can not be left empty" << endl;
          cout << "Enter product*:  ";
          getline(cin, product);
        }
      }
      
      cout << "Enter version:  ";
      getline(cin, version);

      
      cout << "Searching CVEs" << endl;

      int count = 0;      
      auto startTime = chrono::high_resolution_clock::now();
      string cpe = formatCPE(vendor, product, version);

      if (mode == "trie") {
        CPEData* result = trie.search(cpe);
        if (result == nullptr) {
          cout << "CPE not found." << endl;
          // continue;
        } else {
          for (CVEstruct* cve : result->cves) {
              cve->print();
              cout << endl;
            count++;
          }
        }
      }
      
      else if (mode == "tree") {
        auto startTimeRB = chrono::high_resolution_clock::now();
        //it didn't like result :(
        Node* res = RBT.search(cpe);
        if (res != RBT.getNIL()) {
            for (CVEstruct* cve : res->data->cves) {
                cve->print();
                cout << endl;
                count++;
            }
        }
      }
      auto endTime = chrono::high_resolution_clock::now();
      auto duration = chrono::duration_cast<chrono::milliseconds>(endTime - startTime).count();

      if (count == 0) {
        cout << "No matching CVEs found" << endl;
      } else {
        // cout << "CVEs found in trie:  " << foundInTrie << endl;
        // cout << "CVEs in rbtree: " << foundInRBT << endl;
        cout << "Time:  " << duration << endl;
      }
      
    }
     //else {
    //   cout << "No command found" << endl;
    // }
  }
   //after project:
  //functionality for any version/vendor
  //go with the better of the trees
  //probably trie so you can use don't need exact software name
  return 0;
}
