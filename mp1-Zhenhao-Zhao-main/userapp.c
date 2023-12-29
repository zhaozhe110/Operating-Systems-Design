#include <stdio.h>
#include <unistd.h>
int main(void)
{

    FILE *fp;
    pid_t my_pid = getpid();

    fp = fopen("/proc/mp1/status", "w");
    if (!fp) {
        perror("Error opening /proc/mp1/status for writing");
        return 1;
    }

    fprintf(fp, "%d", my_pid);
    fclose(fp);
    // Perform some computation to use CPU time.
    // you could edit iter times for a suitable duration
    volatile long long unsigned int sum = 0;
    for (int i = 0; i < 100000000; i++) {
       volatile long long unsigned int fac = 1;
       for (int j = 1; j <= 200; j++) {
           fac *= j;
       }
       sum += fac;
    }


    fp = fopen("/proc/mp1/status", "r");
    if (!fp) {
        perror("Error opening /proc/mp1/status for reading");
        return 1;
    }
    char c;
    printf("Registered PIDs:\n");
    while ((c = getc(fp)) != EOF) {
        putc(c, stdout);
    }
    fclose(fp);

    return 0;

}
