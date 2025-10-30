#include <vector>
#include <string>
#include <queue>
#include "trie.h"
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

void Trie::insert(string& word) {
    //insert a word into the trie
    TrieNode* current = root;
    bool found;
    for (char c : word) {
        //search until the current node doesn't have the next letter as a child
        found = false;
        for (int i=0; i < current->children.size(); i++) {
            if (current->children[i]->character == c) {
                found = true;
            }
            if (found) {
                current = current->children[i];
            }
            else {
                //create the new node with the character that wasn't found
                TrieNode* newNode = new TrieNode(c);
                current->children.push_back(newNode);
            } 
        }
    }
    current->isWord = true;
}


bool Trie::search(string& word) {
    TrieNode* current = root;
    for (char c : word) {
        for (int i=0; i < current->children.size(); i++) {
            //character isn't in the trie, so doesn't exist
            if (current->children[i]->character != c) {
                return false;
            }
            //does exists, continue to next letter
            current = current->children[i];
        }
    }
    //if it makes it here then the word is in it
    return true;
}


