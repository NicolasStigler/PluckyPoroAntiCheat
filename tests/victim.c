#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>

void handle_sigusr1(int sig) {
    printf("Received SIGUSR1. Attempting execve with LD_PRELOAD...\n");
    char *new_argv[] = { "/bin/true", NULL };
    char *new_envp[] = { "LD_PRELOAD=/tmp/fake.so", NULL };
    
    // This should be blocked by the eBPF agent
    int ret = execve("/bin/true", new_argv, new_envp);
    
    if (ret == -1) {
        printf("execve failed with errno: %d\n", errno);
        if (errno == EPERM) {
             printf("[+] execve blocked with EPERM (Success)\n");
        } else {
             printf("[-] execve failed with unexpected errno\n");
        }
    } else {
        // Should not happen if successful, as process is replaced
        printf("[-] execve executed successfully (Failure)\n");
    }
    fflush(stdout);
}

int main() {
    signal(SIGUSR1, handle_sigusr1);
    printf("Victim process started. PID: %d\n", getpid());
    fflush(stdout);
    while(1) {
        sleep(1);
    }
    return 0;
}