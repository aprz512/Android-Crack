#include <iostream>

using namespace std;

class A
{
    int num1;
    int num2;
    int num3;
    int num4;

public:
    A()
    {
        cout << "A's constructor" << endl;
    }

    ~A()
    {
        cout << "~A" << endl;
    }
    void show()
    {
        cout << "num:" << num1 << endl;
    }
};

A array[];

int main()
{

    A *a0 = new A;
    array[0] = *a0;

    A *a1 = new A;
    array[1] = *a1;

    A *a2 = new A;
    array[2] = *a2;

    A *a3 = new A;
    array[3] = *a3;
}