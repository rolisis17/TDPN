#include <string.h>
#include <iostream>

int main(int ac, char** av){
    std::string answer;
    
    printf("Select:\n0 - connect to TPN\n1 - Become TPN\n");
    std::getline(std::cin, answer);

    printf(answer.c_str(), answer.length());

    return 0;
}