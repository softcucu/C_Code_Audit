// Test C++ file for parser

#define MAX_SIZE 100
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define PRINT_MSG(msg) printf("%s\n", msg)

#include <iostream>
#include <vector>

// Global variables
int global_counter = 0;
const double PI = 3.14159;
static char buffer[256];
extern int external_var;

namespace myns {
    int namespace_var = 42;
}

// Struct declarations
struct Point {
    int x;
    int y;
};

struct Person {
    char name[64];
    int age;
    double height;
};

template<typename T>
struct Container {
    T value;
    int count;
};

struct Node {
    int data;
    Node* next;
    static int node_count;
};

// Function (should not be parsed as global var)
void some_function() {
    int local_var = 10;
}

class MyClass {
    int member;
};

int main() {
    Point p;
    p.x = 10;
    return 0;
}
