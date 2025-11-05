#ifndef CVE_DATA_H
#define CVE_DATA_H
#include <iostream>
#include <string>
#include <vector>
#include "cve_struct.h"
using namespace std;

struct CVEData {
    string id;
    string description;
    string vendor;
    string product;
    string version;

    void print() {
        cout << "ID: " << id << endl;
        cout << "Description: " << description << endl;
    }
};

struct CPEData {
    string cpeName;
    vector<CVEstruct*> cves;

    void print() {
        for (CVEstruct* cve : cves) {
            cve->print();
        }
    }
};


#endif
