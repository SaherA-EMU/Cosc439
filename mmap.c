#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>

int main ()
{
    int x;
    int * ptr;
    
    // this is an example of how a parent and child process can share the same int memory
    ptr = (int*) mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
    
    if (fork() == 0)  // true if this is the child process
    {
        for (x=1; x < 5; x++)
        {
            printf("child: %d\n", (*ptr)++);
            sleep(1);
        }
        exit(0);
    }
    
    // code executed only by the parent process
    for (x=1; x < 5; x++)
    {
	    printf("parent: %d\n", (*ptr)++);
    	sleep(1);
    }
}
