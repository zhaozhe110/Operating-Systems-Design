#include<stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <sys/wait.h>
#include "userapp.h"


void call_yield(int pid){
	FILE *fp = fopen("/proc/mp2/status", "w");
	if(fp == NULL){
		perror("fopen w");
		exit(1);
	}
	char buff[8000];
	snprintf(buff,sizeof(buff),"Y,%d",pid);
	fprintf(fp, "%s", buff);
	fclose(fp);
}
void deregister(int pid){
	FILE *fp = fopen("/proc/mp2/status", "w");
	if(fp == NULL){
		perror("fopen w");
		exit(1);
	}
	char buff[8000];
	snprintf(buff,sizeof(buff),"D,%d",pid);
	fprintf(fp, "%s", buff);
	fclose(fp);
}
void job(){
    int n = 30; 
    unsigned long long factorial = 1;
    for(int i = 1; i <= n; ++i) {
        factorial *= i;
    }

}
int main(int argc, char* argv[])
{
	unsigned long period;
	unsigned long computation;
	unsigned long jobs = 5;
	if(argc == 4){
		period = atoi(argv[1]);
		computation = atoi(argv[2]);
		jobs = atoi(argv[3]);
	}else if(argc == 3){
		period = atoi(argv[1]);
		computation = atoi(argv[2]);
	}

	FILE *fp = fopen("/proc/mp2/status", "w");
	if(fp == NULL){
		perror("fopen w");
		return 1;
	}

	pid_t pid = getpid();
	//register
	char buff[8000];
	snprintf(buff,sizeof(buff),"R,%d,%lu,%lu", (int)pid, period, computation);
	fprintf(fp, "%s", buff);

	fclose(fp);


    struct timespec t0, current_time;
    double wakeup_time, process_time;

    // start time
    clock_gettime(CLOCK_MONOTONIC, &t0); 

	call_yield((int)pid);

	int time = 0;
	while(time < jobs){
		//job
        clock_gettime(CLOCK_MONOTONIC, &current_time);
        wakeup_time = (current_time.tv_sec - t0.tv_sec) * 1000.0 + (current_time.tv_nsec - t0.tv_nsec) / 1000000.0; 

        printf("pid: %d, wake up time:\t%.0f ms\n", (int)pid, wakeup_time);

		time++;
		job();

        struct timespec job_end_time;
        clock_gettime(CLOCK_MONOTONIC, &job_end_time);
        process_time = (job_end_time.tv_sec - current_time.tv_sec) * 1000000.0 + (job_end_time.tv_nsec - current_time.tv_nsec);

        printf("pid: %d, process time:\t%.0f ns\n", (int)pid, process_time);

		call_yield((int)pid);

	}
	deregister((int)pid);
	return 0;
}