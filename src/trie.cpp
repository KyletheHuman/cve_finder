#include <vector>
#include <string>
#include <queue>
#include "trie.h"
#include "cve_data.h"
using namespace std;

Trie::Trie() {
    root = new TrieNode();
}

Trie::~Trie() {
    queue<TrieNode*> q;
    q.push(root);
    while (!q.empty()) {
        for (auto& child : q.front()->children) {
            q.push(child);
        }
        delete q.front();
        q.pop();
    }

}

//helper for insert, checks if c is a node's child
TrieNode* Trie::findChild(TrieNode* node, char c) {
    for (TrieNode* child : node->children) {
        if (child->character == c) {
            return child;
        }
    }
    return nullptr;
}

void Trie::insert(string& cpeName, CVEData* data) {
    //insert a word into the trie
    TrieNode* current = root;
    for (char c : cpeName) {
        TrieNode* child = findChild(current, c);
        if (child == nullptr) {
            TrieNode* newNode = new TrieNode(c);
            current->children.push_back(newNode);
            current = newNode;
        }
        else {
            current = child;
        }
    }
    current->isLeaf = true;
    if (!current->data) {
            current->data = new CPEData();
            current->data->cpeName = cpeName;
        }
        current->data->cves.push_back(data);
}


CPEData* Trie::search(string& name) {
    TrieNode* current = root;
    for (char c : name) {
        TrieNode* child = findChild(current, c);
        if (child == nullptr) {
            return nullptr;
        }
        current = child;
    }
    if (current->isLeaf) {
        return current->data;
    }
    return nullptr;
}

void Trie::print(TrieNode* node = nullptr, string prefix = "") {
    if (!node) {
        node = root;
    }

    if (node->isLeaf && node->data) {
        node->data->print();
    }

    for (TrieNode* child : node->children) {
        print(child, prefix + child->character);
    }
}


