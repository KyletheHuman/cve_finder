#include "cve_struct.h"
#include "api_processor.h"
#include "file_checker.h"

#include <iostream>
#include <string>
#include <vector>
using namespace std;

int main (int argc, char* argv[]) {
  cout << "CVE Finder" << endl;
  cout << "commands: update, load, search, exit" << endl;

  vector<CVEstruct> cves; //stores all cves
  string command;

  while(true) {
    getline(cin, command);
    command = cleanInput(command);
    
    if (command == "exit") {
      break;
      
    } else if (command == "update") {
      cout << "Updating CVE data" << endl;
      updateData();
      cves = loadData();
      
    } else if (command == "load") {
      cout << "Loading CVE data" << endl;
      cves = loadData();
      if (cves.empty()) {
        cout << "No local data. Try update" << endl;
      }
      
    } else if (command == "search") {
      if (cves.empty()) {
        cout << "No local data. Try load or update" << endl;
        continue;
      }
      
      string vendor;
      string product;
      string version;
      
      cout << "Search - leave blank for any except product" << endl;
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
      //figure out how to search them in the trees

      if (count == 0) {
        cout << "No matching CVEs found" << endl;
      } else {
        //prints
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
