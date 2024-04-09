// Based on:
// https://en.cppreference.com/w/cpp/language/try_catch

#include <iostream>
#include <vector>

void foo(void) {
    std::cout << "Throwing an integer exception...\n";
    throw 42;
}

void bar(void) {
    try {
        foo();
    }
    catch (const std::exception& e) {
        std::cout << "Standard exception was caught, with message: '"
                  << e.what() << "'\n";
    }
}

int main()
{
    try
    {
        std::cout << "Throwing an integer exception...\n";
        throw 42;
    }
    catch (int i)
    {
        std::cout << "Integer exception was caught, with value: " << i << '\n';
    }

    try
    {
        bar();
    }
    catch (int i)
    {
        std::cout << "Integer exception was caught, with value: " << i << '\n';
    }
 
    try
    {
        std::cout << "Creating a vector of size 5... \n";
        std::vector<int> v(5);
        std::cout << "Accessing the 11th element of the vector...\n";
        std::cout << v.at(10); // vector::at() throws std::out_of_range
    }
    catch (int i)
    {
        std::cout << "Integer exception was caught, with value: " << i << '\n';
    }
    catch (const std::exception& e) // caught by reference to base
    {
        std::cout << "Standard exception was caught, with message: '"
                  << e.what() << "'\n";
    }
}
