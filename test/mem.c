#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>

int main() {
    pid_t pid = getpid();
    
    printf("PID: %d\n", pid);
    
    int value = 1337;

    printf("Address: %p\n", &value);

    int* im_on_the_heap = (int*) malloc(4);

    im_on_the_heap[0] = value;

    while (1) {
        value++;
        
        printf("Value: %d\n", value);

        fflush(stdout);
        
        usleep(1000 * 1000); // 1000 ms = 1000 * 1000 us
    }
    
    return 0;
}
