#ifndef __PROCESS_LC_H
#define __PROCESS_LC_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 255

struct event {
    int pid;
    int ppid;
    unsigned long long duration_ns;
    char cmd_name[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    _Bool exit_event;
    unsigned exit_code;
};

#endif /* __PROCESS_LC_H */
