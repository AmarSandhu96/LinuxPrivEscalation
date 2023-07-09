#include <iostream>
#include <fstream>

int main(int argc, char* argv[])
{
    std::ifstream file;
    file.open("root_files.txt");
    std::string data;
    std::cout << "Entering Loop" << std::endl;
    if (file.is_open())
    {

    
        while(std::getline(file, data))
        {
            if (data.find("/usr/local/bin") != std::string::npos)
            {
            
            
                std::cout << "strace " + data + " 2<&1 | grep -iE \"home\" | grep -iE \"open|access|no such file\" " << std::endl;;
                std::system(("strace " + data + " 2<&1 | grep -iE \"home\" | grep -iE \"open|access|no such file\" ").c_str());
            }
        }
    }
    return 0;
}
