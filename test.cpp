#include <iostream>
#include <vector>
#include <map>
#define _NEWLINE putchar('\n');

int main()
{

    std::map<std::string, std::string> map;
    map["cat -n /$HOME/../../etc/passwd"] = "/etc/passwd";
    map["cat -n /$HOME/../../etc/shadow"] = "/etc/shadow";
    map["cat -n /$HOME/../../pwd.db"] = "/etc/pwd.db";

    for (const auto& i:  map)
    {
        std::cout << i.second << std::endl;
        _NEWLINE;
        std::system((i.first).c_str());
        _NEWLINE;
    }
    return 0;
}
