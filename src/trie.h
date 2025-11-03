#include <vector>
#include <iostream>
#include "cve_data.h"
#pragma once
using namespace std;
struct TrieNode {
    bool isLeaf;
    char character;
    CPEData* data;

    vector<TrieNode*> children;

    TrieNode(char character='*') {
        isLeaf = false;
        data = nullptr;
        this->character = character;
    }

    void printData() {
        data->print();
    }
};

class Trie {
    TrieNode* root;


    Trie();
    ~Trie();

    TrieNode* findChild(TrieNode* node, char c);
    void insert(string& cpeName, CVEData* data);
    CPEData* search(string& word);
    void Trie::print(TrieNode* node = nullptr, string prefix = "");
};