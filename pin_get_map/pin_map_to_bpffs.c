#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <string.h>
#include "bpf.h"

static const char *path_to_stack = "/sys/fs/bpf/my_first_stack";

int main(int argc, char **argv) {
	// create stack typed map
	int stack_fd = bpf_create_map(BPF_MAP_TYPE_STACK, 0, sizeof(int), 10, 0);
	if (stack_fd < 0) {
		printf("Create stack failed [%d]: %s\n", stack_fd, strerror(errno));
		return -1;
	} 

	// populate the stack
	int i;
	for (i=0;i<10;i++)
		bpf_map_update_elem(stack_fd, NULL, &i, BPF_ANY);

	// pin the stack to bpffs
	int pin_rslt = bpf_obj_pin(stack_fd, path_to_stack);
	if (pin_rslt < 0) {
		printf("Pin stack to bpffs [%d]: %s\n", pin_rslt, strerror(errno));
		return -1;
	}

	printf("[OK] save stack to %s !\n", path_to_stack);
	return 0;
}
