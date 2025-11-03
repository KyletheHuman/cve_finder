#include <string>
#include <vector>
#pragma once
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
    vector<CVEData*> cves;

    void print() {
        for (CVEData* cve : cves) {
            cve->print();
        }
    }
};