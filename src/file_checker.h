#pragma once
#include <iostream>
#include <string> //in case
#include <algorithm>
#include <fstream>

using namespace std;


//checks if any data in data/cve data
inline bool checkFile(const string &path);

//clean up string to be consistent in searches cleanInput
//remove quotes
//lowercase
//remove spaces between version and software with -
//keep only letters and nums
inline string cleanInput(const string &in);



