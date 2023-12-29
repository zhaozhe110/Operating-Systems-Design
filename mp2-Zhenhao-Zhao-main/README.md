[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-24ddc0f5d75046c5622901739e7c5dd533143b0c8e959d652212380cedb1ea36.svg)](https://classroom.github.com/a/eFhgTmgw)
# UIUC CS 423 MP2

Your Name: Zhenhao Zhao

Your NetID: zz110

## Overview

The MP2 module is designed as a Linux kernel module to manage scheduling for real-time user-space processes. It utilizes a simplified real-time scheduler model based on fixed-priority scheduling (the shorter the period, the higher the priority) and includes functionalities for registering tasks, yielding the processor, and performing admission control. Below is a detailed explanation of how various components are implemented.

## Design Decisions and Implementations

### Task Structure

Each task managed by the MP2 scheduler is represented by an `mp2_task_struct` structure, which includes information such as the task's PID, scheduling parameters (period and processing time), state, and Linux task struct pointer. The tasks are maintained in a linked list with necessary operations protected by mutexes to prevent concurrent modification.

### Admission Control

Admission control is crucial to ensuring that the system does not accept more tasks than it can handle, maintaining system schedulability. When a task tries to register, the scheduler calculates the CPU utilization of the system considering the new task. If the total utilization exceeds a specific threshold (in this case, we use the classic Rate Monotonic Scheduling (RMS) threshold of 69.3% for n processes), the task is not admitted, and an error is returned. This calculation is performed in the `status_write` function when handling the 'R' (Register) command.

### Yield Functionality

The YIELD operation is designed to allow a task to relinquish the CPU, allowing the scheduler to allocate processing time to other tasks. When a task calls YIELD (represented by the 'Y' command in the `status_write` function), the scheduler marks the task as SLEEPING and sets up a timer to wake up the task for its next period. The task itself is put into an uninterruptible sleep state, ensuring it doesn't run until the scheduler explicitly wakes it up. This mechanism ensures tasks don't utilize CPU time beyond their allocated processing time and adheres to real-time constraints.

### Dispatching Thread

The core of the MP2 scheduler is the dispatching thread, implemented in the `dispatching_thread_fn` function. This thread is responsible for making scheduling decisions, primarily selecting the highest priority task (based on the shortest period) and managing task states. The thread sleeps when not needed and is woken up when tasks are ready to run or when a task yields the processor.

When deciding to schedule a task, the dispatching thread sets the appropriate scheduling policy and priority for the task's Linux `task_struct`. It ensures that running tasks are demoted to normal scheduling policies and newly scheduled tasks are set to real-time policies. This thread is also where tasks are set to the RUNNING or READY states based on scheduling decisions.

### Timer Mechanism

Timers are utilized for each task to manage their wake-up times after yielding. The `wake_up_timer_handler` is called when a timer expires, marking the task as READY and waking up the dispatching thread. This mechanism ensures that tasks resume execution after their sleeping period accurately, adhering to real-time scheduling principles.

### Proc Filesystem Interface

The module uses the proc filesystem for interaction with user-space. It creates a directory (`mp2`) and a file (`status`) within the /proc system. The `status` file is used by user-space applications to register, deregister, and yield tasks using write operations and to query the current list of tasks with read operations.


Certainly, I'll add a section about the user-level application, often referred to as `userapp`, in the README. This application communicates with the kernel module and is responsible for registering/deregistering tasks and yielding the processor after a task's execution. Here's how you can incorporate it:

### User-Level Application: userapp

Run the `userapp` with period and computation time arguments:

```sh
./userapp [PERIOD] [COMPUTATION_TIME]
```

- `PERIOD`: The time in milliseconds between subsequent runs of the real-time task.
- `COMPUTATION_TIME`: The execution time in milliseconds that the task requires within each period.

The application performs these main functions:

1. **Registration**: It registers the current process as a real-time task by writing "R,[PID],[PERIOD],[COMPUTATION_TIME]" to `/proc/mp2/status`. The kernel module checks if the task can be admitted based on its scheduling guarantees.

2. **Yielding**: After completing its execution for a period, the task informs the scheduler by writing "Y,[PID]" to `/proc/mp2/status`. It then gets blocked, and the scheduler will wake it up for the next period.

3. **Deregistration**: Upon completion of its required job cycles, the task deregisters itself by writing "D,[PID]" to `/proc/mp2/status`, effectively informing the scheduler that it no longer requires real-time service.



