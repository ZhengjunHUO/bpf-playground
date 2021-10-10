#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <string.h>
#include "bpf.h"

static const char *path_to_stack = "/sys/fs/bpf/my_first_stack";

int main(int argc, char **argv) {
	// load stack from bpffs 	
	int stack_fd = bpf_obj_get(path_to_stack);
	if (stack_fd < 0) {
		printf("Load stack failed [%d]: %s\n", stack_fd, strerror(errno));
		return -1;
	} 

	// pop out elems from stack
	int i, rslt;
	for (i=0;i<10;i++) {
		bpf_map_lookup_and_delete_elem(stack_fd, NULL, &rslt);
		printf("Pop value [%d] from stack.\n", rslt);
	}

	return 0;
}
