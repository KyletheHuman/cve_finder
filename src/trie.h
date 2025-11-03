#include <vector>
#pragma once
using namespace std;
struct TrieNode {
    bool isLeaf;
    char character;

    vector<TrieNode*> children;

    TrieNode(char character=' ') {
        isLeaf = false;
        this->character = character;
    }
};

class Trie {
    TrieNode* root;


    Trie();
    ~Trie();

    void insert(string& word);
    bool search(string& word);
};