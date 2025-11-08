#include "RedBlackTree.h"
#include <iostream>

RedBlackTree::RedBlackTree() {
    NIL = new Node(0);
    NIL->color = Color::BLACK;
    NIL->left = NIL->right = NIL;
    NIL->parent = nullptr;
    root = NIL;
}

RedBlackTree::~RedBlackTree() {
    clear();
    delete NIL;
}

void RedBlackTree::clear() {
    deleteSubtree(root);
    root = NIL;
}

void RedBlackTree::deleteSubtree(Node* node) {
    if (!node || node == NIL) return;
    deleteSubtree(node->left);
    deleteSubtree(node->right);
    delete node;
}

void RedBlackTree::leftRotate(Node* x) {
    Node* y = x->right;

    x->right = y->left;
    if (y->left != NIL) y->left->parent = x;

    y->parent = x->parent;
    if (x->parent == nullptr) {
        root = y;
        y->parent = nullptr; // explicit root parent
    } else if (x == x->parent->left) {
        x->parent->left = y;
    } else {
        x->parent->right = y;
    }

    y->left = x;
    x->parent = y;
}

void RedBlackTree::rightRotate(Node* x) {
    Node* y = x->left;

    x->left = y->right;
    if (y->right != NIL) y->right->parent = x;

    y->parent = x->parent;
    if (x->parent == nullptr) {
        root = y;
        y->parent = nullptr; // explicit root parent
    } else if (x == x->parent->right) {
        x->parent->right = y;
    } else {
        x->parent->left = y;
    }

    y->right = x;
    x->parent = y;
}

void RedBlackTree::fixInsert(Node* k) {
    while (k != root && k->parent->color == Color::RED) {
        if (k->parent == k->parent->parent->left) {
            Node* u = k->parent->parent->right; // uncle
            if (u->color == Color::RED) {
                // Case 1: recolor and move up
                k->parent->color = Color::BLACK;
                u->color = Color::BLACK;
                k->parent->parent->color = Color::RED;
                k = k->parent->parent;
            } else {
                if (k == k->parent->right) {
                    // Case 2: transform to LL
                    k = k->parent;
                    leftRotate(k);
                }
                // Case 3: rotate at grandparent
                k->parent->color = Color::BLACK;
                k->parent->parent->color = Color::RED;
                rightRotate(k->parent->parent);
            }
        } else {
            Node* u = k->parent->parent->left; // uncle
            if (u->color == Color::RED) {
                // mirror Case 1
                k->parent->color = Color::BLACK;
                u->color = Color::BLACK;
                k->parent->parent->color = Color::RED;
                k = k->parent->parent;
            } else {
                if (k == k->parent->left) {
                    // mirror Case 2
                    k = k->parent;
                    rightRotate(k);
                }
                // mirror Case 3
                k->parent->color = Color::BLACK;
                k->parent->parent->color = Color::RED;
                leftRotate(k->parent->parent);
            }
        }
    }
    root->color = Color::BLACK;
}

void RedBlackTree::insert(string& cpeName, CVEstruct* cve) {
    // root = insertHelper(this->root, cpeName, cve);
    Node* current = root;
    Node* parent = nullptr;

    while (current != NIL) {
        parent= current;

        if (cpeName == current->data->cpeName) {
            current->data->cves.push_back(cve);
        }

        if (cpeName < current->data->cpeName) {
            current = current->left;
        } else {
            current = current->right;
        }
    }
    CPEData* cpe = new CPEData(cpeName);
    cpe->cves.push_back(cve);

    Node* newNode = new Node(cpe);
    newNode->left = newNode->right = NIL;
    newNode->parent = parent;
    newNode->color = Color::RED;

    if (parent == nullptr || parent == NIL) {
        root = newNode;
        newNode->parent = nullptr;
    }
    else if (cpeName < parent->data->cpeName) {
        parent->left = newNode;
    }
    else {
        parent->right = newNode;
    }
    fixInsert(newNode);
}

// Node* RedBlackTree::insertHelper(Node* node, string &cpeName, CVEstruct* cve) {
//     // Node* z = new Node(data);
//     // z->left = z->right = NIL;

//     // Node* y = nullptr;
//     // Node* x = root;

//     // // BST insert
//     // while (x != NIL) {
//     //     y = x;
//     //     x = (z->data < x->data) ? x->left : x->right;
//     // }
//     // z->parent = y;

//     // if (y == nullptr) {
//     //     root = z;
//     // } else if (z->data < y->data) {
//     //     y->left = z;
//     // } else {
//     //     y->right = z;
//     // }

//     // // fix-up
//     // if (z->parent == nullptr) {
//     //     z->color = Color::BLACK; // root must be black
//     //     return;
//     // }
//     // if (z->parent->parent == nullptr) {
//     //     return; // parent is root, red parent w/ black root is fine
//     // }
//     if (!node) {
//         CPEData* cpe = new CPEData(cpeName);
//         return new Node(cpe);
//     }

//     if (node->data->cpeName < cpeName) {
//         node->left = insertHelper(node->left, cpeName, cve);
//     }
//     else if (node->data->cpeName > cpeName) {
//         node->right = insertHelper(node->right, cpeName, cve);
//     }
//     else if (node->data->cpeName == cpeName) {
//         node->data->cves.push_back(cve);
//     }
//     fixInsert(node);
//     return node;
// }

Node* RedBlackTree::searchHelper(Node* node, string data) const {
    if (node == NIL || node->data->cpeName == data) return node;
    return (data < node->data->cpeName) ? searchHelper(node->left, data)
                               : searchHelper(node->right, data);
}

Node* RedBlackTree::search(string data) const {
    return searchHelper(root, data);
}

void RedBlackTree::inorderHelper(Node* node) const {
    if (node == NIL) return;
    inorderHelper(node->left);
    std::cout << node->data << ' ';
    inorderHelper(node->right);
}

void RedBlackTree::inorder() const { inorderHelper(root); }

// ----- Validation -----
bool RedBlackTree::validate(std::string* err) const {
    // Root must be black (unless empty)
    if (root != NIL && root->color != Color::BLACK) {
        if (err) *err = "Root is not black";
        return false;
    }
    int targetBlack = -1;
    return validateRec(root, 0, targetBlack, err);
}

bool RedBlackTree::validateRec(const Node* n, int currentBlack, int& targetBlack, std::string* err) const {
    if (n == NIL) {
        // count NIL as a black leaf in black-height
        if (targetBlack == -1) targetBlack = currentBlack + 1;
        return (currentBlack + 1) == targetBlack;
    }

    // red node cannot have red child
    if (n->color == Color::RED) {
        if (n->left->color == Color::RED || n->right->color == Color::RED) {
            if (err) *err = "Red node has red child at key " + n->data->cpeName;
            return false;
        }
    }

    int nextBlack = currentBlack + (n->color == Color::BLACK ? 1 : 0);
    return validateRec(n->left, nextBlack, targetBlack, err) &&
           validateRec(n->right, nextBlack, targetBlack, err);
}

std::pair<int,int> RedBlackTree::countColors() const {
    int reds = 0, blacks = 0;
    countRec(root, reds, blacks);
    return {reds, blacks};
}

void RedBlackTree::countRec(const Node* n, int& r, int& b) const {
    if (n == NIL) return;
    if (n->color == Color::RED) ++r; else ++b;
    countRec(n->left, r, b);
    countRec(n->right, r, b);
}
