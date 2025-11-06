#include <iostream>

#include "trie.h"
#include "file_checker.h"
#include "api_processor.h"

using namespace std;

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
        //get input for vendor, product, and version
        //prompt for action
        break;
    }

}
