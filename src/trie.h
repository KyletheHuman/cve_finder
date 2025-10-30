#include <vector>

using namespace std;
struct TrieNode {
    bool isWord;
    char character;

    vector<TrieNode*> children;

    TrieNode(char character=' ') {
        isWord = false;
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