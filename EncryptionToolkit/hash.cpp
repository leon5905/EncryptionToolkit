// minglee.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
#include "sha512.h"
using namespace std;

 
using std::string;
using std::cout;
using std::endl;
 
int main(int argc, char *argv[])
{
    string input ;
    string output1 = sha512(input);
 
	cout<<"Enter input: ";
	cin>>input;
    cout << "sha512('"<< input << "'):" << output1 << endl;
    return 0;
}
