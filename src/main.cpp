#include <iostream>

#include "trie.h"
#include "file_checker.h"
#include "api_processor.h"

using namespace std;

string formatCPE(string vendor, string product, string version) {
    return vendor + "-" + product + "-" + version;
}

// yoink mass data dumps for each year of cve's:
//cURL all of NVD's API feeds from each year as .gz compressed files
//decompress into normal json
//nholmann github json to parse
//store each CVE entry as a struct in array
//insert structs into trees
//build so that search by version
//time to search for both inputs
//print list
// *after due date optimize to use better structure*
void main() {

    //insert load results into tree and trie
    //handle search inputs in while loop


    //load the data into vector
    //give an error if there isn't anything
    vector<CVEstruct> data = loadData();
    if (data.empty()) {
        cout << "Error loading data :(" << endl;
        return;
    }

    Trie trie;
    //Tree tree;
    for (CVEstruct cve : data) {
        string cpe = cve.cpe();
        trie.insert(cpe, &cve);
        //TODO: INSERT INTO TREE
    }


    //loop until end
    while (true) {
        //set mode to tree or trie
        string mode;
        cout << "Enter the mode (tree or trie): ";
        cin >> mode;
        cout << endl;

        //prompt for action
        string choice;
        cout << "What would you like to do (search, update, exit)? ";
        cin >> choice;

        if (choice == "search") {
            //get input for vendor, product, and version
            string vendor, product, version;
            cout << "Enter the software's vendor: ";
            cin >> vendor;
            cout << "Enter the software's product: ";
            cin >> product;
            cout << "Enter the software's version: ";
            cin >> version;

            if (mode == "trie") {
                string cpe = formatCPE(vendor, product, version);
                CPEData* result = trie.search(cpe);

                if (result == nullptr) {
                    cout << "CPE not found." << endl;
                    continue;
                }
                for (CVEstruct* cve : result->cves) {
                    cve->print();
                }
            }
            //TODO:: Tree
        }
        else if (choice == "update") {
            updateData();
        }
        else if (choice == "exit") {
            break;
        }
        else {
            cout << "Error: choice not recognized." << endl;
        }
    }

}
