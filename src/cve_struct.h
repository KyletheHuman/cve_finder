#include <iostream>
#include <string> //just in case

struct CVEstruct {
  string id;
  string description;
  double cvss3score;
  string productversion;

  void print() {
        cout << "ID: " << id << endl;
        cout << "Description: " << description << endl;
    }
};
