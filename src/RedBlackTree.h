#ifndef REDBLACKTREE_H
#define REDBLACKTREE_H

#include <string>
#include <utility>

#include "cve_struct.h"
#include "cve_data.h"

enum class Color { RED, BLACK };

struct Node {
    CPEData* data;
    Color color;
    Node *left, *right, *parent;

    explicit Node(CPEData* d)
        : data(d), color(Color::RED), left(nullptr), right(nullptr), parent(nullptr) {}
};

class RedBlackTree {
public:
    RedBlackTree();
    ~RedBlackTree();

    RedBlackTree(const RedBlackTree&)            = delete; // avoid accidental deep copy
    RedBlackTree& operator=(const RedBlackTree&) = delete;
    RedBlackTree(RedBlackTree&&)                 = delete;
    RedBlackTree& operator=(RedBlackTree&&)      = delete;

    void insert(string& cpeName, CVEstruct* cve);
    Node* search(string cpe) const;  // returns NIL if not found

    void inorder() const;
    void clear();                                // remove all nodes (keeps sentinel)

    Node* getRoot() const { return root; }
    Node* getNIL()  const { return NIL;  }

    // Debug/validation helpers
    bool validate(std::string* errMsg = nullptr) const;
    std::pair<int, int> countColors() const; // {reds, blacks} (excludes NIL)

    Node* getRoot() {
        return root;
    }

private:
    Node* root;
    Node* NIL; // sentinel (always BLACK)

    // rotations
    void leftRotate(Node* x);
    void rightRotate(Node* x);

    // fix after insert
    void fixInsert(Node* k);
    Node* insertHelper(Node* node, string& cpeName, CVEstruct* cve);

    // helpers
    void inorderHelper(Node* node) const;
    Node* searchHelper(Node* node, string data) const;

    // memory
    void deleteSubtree(Node* node);

    // validation internals
    bool validateRec(const Node* n, int currentBlack, int& targetBlack, std::string* err) const;
    void countRec(const Node* n, int& r, int& b) const;
};

#endif // REDBLACKTREE_H
