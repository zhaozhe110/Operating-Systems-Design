# UIUC CS 423 MP1

Your Name: Zhenhao Zhao

Your NetID: zz110

---

### **MP1 Kernel Module Implementation Overview**

#### **1. Interactions using the Proc File System:**

- **Proc File Creation**: We've created a directory `/proc/mp1` and a status file `/proc/mp1/status` within the kernel module.
- **User Interaction**: The user can interact with the module by writing to and reading from the `/proc/mp1/status` file.
    - *Writing*: ```command
                echo "1" > /proc/mp1/status  # registering PID 1 to the module.
                ``` A user-space application can also register a PID by writing it into this file.
    - *Reading*: ```command: cat /proc/mp1/status```

        On reading this file, users can see a list of registered PIDs and their CPU usage.

#### **2. Storing Process Information:**

- We utilize the kernel's linked list to store process information.
- Each node (of type `struct pid_entry`) consists of a PID, user time, and list pointers.
- Process entries are dynamically allocated and added to the `pid_list` global list when a PID is registered. If a process dies or an error occurs during retrieval of CPU time, the corresponding entry is removed from the list.

#### **3. Periodical Tasks using Timer and Workqueue:**

- **Timer**: A timer is initialized to fire every 5 seconds. On each expiry, it schedules a work task to retrieve CPU usage of registered PIDs.
- **Workqueue**: The work task (`update_user_time_work`) runs in a dedicated workqueue (`mp1_workqueue`). When this work is executed, it iterates over the `pid_list`, fetches the CPU usage of each PID, and updates the list with the latest values.


#### **4. Concurrency Considerations:**

- A mutex (`process_list_mutex`) is used to ensure that concurrent accesses to the `pid_list` (like during read, write, or updates) are synchronized, preventing potential race conditions.

#### **5. Example:**
```
root@q:~/cs423/mp1-Zhenhao-Zhao# ./userapp
[ 2025.037861][  T999] PID: 1594, CPU Time: 486949356
[ 2030.169469][  T999] PID: 1594, CPU Time: 3950395251
[ 2035.281090][  T999] PID: 1594, CPU Time: 6016625798
[ 2040.398215][  T999] PID: 1594, CPU Time: 8208909690
Registered PIDs:
1594: 8208909690
```
Multiple process example
```
$ ./userapp
Registered PIDs:
18741: 15172000000
18740: 15876000000

$ cat /proc/mp1/status
18741: 15172000000
18740: 15876000000

dmesg
[168014.108432] MP1 module loaded.
[168024.401181] PID: 18741, CPU Time: 1140000000
[168024.401185] PID: 18740, CPU Time: 1980000000
[168029.517951] PID: 18741, CPU Time: 4644000000
[168029.517956] PID: 18740, CPU Time: 5512000000
[168034.637711] PID: 18741, CPU Time: 8196000000
[168034.637716] PID: 18740, CPU Time: 9048000000
[168039.758174] PID: 18741, CPU Time: 11648000000
[168039.758178] PID: 18740, CPU Time: 12328000000
[168044.877130] PID: 18741, CPU Time: 15172000000
[168044.877133] PID: 18740, CPU Time: 15876000000
[168083.972487] MP1 module unloaded.

```
---
