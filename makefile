all: privesc

privesc: privesc.cpp
	g++ -o privesc.elf privesc.cpp -g -static
	./privesc.elf -scan

