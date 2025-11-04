#pragma once
#include <iostream>
#include <string> //in case
#include <algorithm>
#include <fstream>

using namespace std;


//checks if any data in data/cve data
inline bool checkFile(const string &path) {
  ifstream file(path);  //try to open
  if (!file.is_open()) {
    return false;
  }

  file.peek();
  bool datapresent;
  if (!file.eof()) {
    datapresent = true;
  } else {
    datapresent = false;
  }  
  file.close();
  return datapresent;
}

//clean up string to be consistent in searches cleanInput
//remove quotes
//lowercase
//remove spaces between version and software with -
//keep only letters and nums
inline string cleanInput(const string &in) {
  string input = in;
  

  //remove quotes
  if (!input.empty() && (input.front() == '"' || input.front() == '\'')) {
    input.erase(0,1);
  }
  if (!input.empty() && (input.back() == '"' || input.back() == '\'')) {
    input.pop_back();
  }

  //lowercase it
  for (size_t i = 0; i < input.size(); ++i) {
     if (input[i] >= 'A' && input[i] <= 'Z') {
        input[i] = input[i] + ('a' - 'A'); // maybe works*
     }  
  }
  
  //replace spaces and slashes with -
  for (size_t i = 0; i < input.size(); ++i) {
    if (input[i] == ' ' || input[i] == '/' || input[i] == '\\') {
      input[i] = '-';
    }  
  }

  // keep only letters and nums and . and - and gets rid of - on ends
  string fixed;
  for (size_t i = 0; i < input.size(); ++i) {
    char c = input[i];
    if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-') {
      fixed += c;
    }  
  }  
  if (!fixed.empty() && fixed[0] == '-') {
    fixed.erase(0,1);
  }
  if (!fixed.empty() && fixed.back() == '-') {
    fixed.pop_back();
  }

  return fixed;
}



