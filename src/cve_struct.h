#include <iostream>
#include <string> //just in case
#pragma once
using namespace std;

struct CVEstruct {
  string id;
  string description;
  double cvss3score;
  string vendor;
  string product;
  string version;

  void print() {
        cout << "ID: " << id << endl;
        cout << "CVSS3.0 score: " << cvss3score << endl;
        cout << "Description: " << description << endl;
    }

  string cpe() {
    return vendor + "-" + product + "-" + version;
  }
};
