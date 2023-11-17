privesc: src/privesc.cpp
	g++ -o bin/privesc.elf src/privesc.cpp -g -static
	bin/privesc.elf -scan

