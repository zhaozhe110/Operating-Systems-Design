#include <bpf.h>
#include <errno.h>
#include <libbpf.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>
#include <limits.h>
#define EXE "./blocker_kern.o"


struct port_rule {
    __u8 udp_action;
    __u8 tcp_action;
};

void add_filter_rule(int map_fd, uint32_t key, struct port_rule rule) {

  int result = bpf_map_update_elem(map_fd, &key, &rule, BPF_ANY);
  if (result) {
    perror("bpf_map_update_elem");
  } else {
    printf("Added rule for port %d\n", key);
  }
}

const char *pin_basedir = "/sys/fs/bpf";
const char *map_filename = "port_map";

int pin_map(int map_fd, const char *filename) {
    char fullpath[PATH_MAX];

    snprintf(fullpath, sizeof(fullpath), "%s/%s", pin_basedir, filename);
    return bpf_obj_pin(map_fd, fullpath);
}

int unpin_map(const char *filename) {
    char fullpath[PATH_MAX];

    snprintf(fullpath, sizeof(fullpath), "%s/%s", pin_basedir, filename);
    return unlink(fullpath);
}

void signal_handler(int signum) {
  if (signum == SIGINT || signum == SIGTERM) {
          if (unpin_map(map_filename) < 0) {
        perror("Error unpinning map");

    }
  }
}
int main(int argc, char **argv) {
  struct bpf_object *obj;
  struct bpf_program *prog;
  int prog_fd;
  int ifindex;
  int err;
  int map_progs_xdp_fd;

      char map_path[PATH_MAX];
    snprintf(map_path, PATH_MAX, "%s/%s", pin_basedir, map_filename);

  if (strcmp(argv[1], "add_rule") == 0){
           if (argc != 4) {
            fprintf(stderr, "Usage: %s add_rule <port> <protocol>\n", argv[0]);
            return 1;
        }

        uint32_t port = atoi(argv[2]);
        struct port_rule rule = { .udp_action = XDP_PASS, .tcp_action = XDP_PASS };

        if (strcmp(argv[3], "tcp") == 0) {
            rule.tcp_action = XDP_DROP;
        } else if (strcmp(argv[3], "udp") == 0) {
            rule.udp_action = XDP_DROP;
        } else {
            fprintf(stderr, "Invalid protocol. Use 'tcp' or 'udp'\n");
            return 1;
        }

        obj = bpf_object__open(EXE);
        if (libbpf_get_error(obj)) {
            perror("bpf_object__open");
            return 1;
        }

        err = bpf_object__load(obj);
        if (err) {
            perror("bpf_object__load");
            return 1;
        }

        map_progs_xdp_fd = bpf_obj_get(map_path);
        if (map_progs_xdp_fd < 0) {
            fprintf(stderr, "Error: bpf_object__find_map_fd_by_name failed\n");
            return 1;
        }

        add_filter_rule(map_progs_xdp_fd, port, rule);
        return 0;
    
  }
  else{
    if (argc != 2) {
      fprintf(stderr, "Usage: %s <interface index>\n", argv[0]);
      return 1;
    }

    // Get network interface index
    ifindex = atoi(argv[1]);

    // Open BPF object file
    obj = bpf_object__open(EXE);
    if (libbpf_get_error(obj)) {
      perror("bpf_object__open");
      return 1;
    }

    // Load BPF program
    err = bpf_object__load(obj);
    if (err) {
      perror("bpf_object__load");
      return 1;
    }

    map_progs_xdp_fd = bpf_object__find_map_fd_by_name(obj, "port_map");
    if (map_progs_xdp_fd < 0) {
      fprintf(stderr, "Error: bpf_object__find_map_fd_by_name failed\n");
      return 1;
    }

      if (pin_map(map_progs_xdp_fd, map_filename) < 0) {
            perror("Error pinning map");
            return 1;
        }
    // Find the XDP program
    prog = bpf_object__find_program_by_name(obj, "xdp_filter_by_port");
    if (!prog) {
      fprintf(stderr, "bpf_object__find_program_by_title failed\n");
      return 1;
    }

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
      perror("bpf_program__fd");
      return 1;
    }

    // Attach the BPF program
    int xdp_flags = 0;
    xdp_flags |= XDP_FLAGS_SKB_MODE;

    if (bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags) < 0) {
      fprintf(stderr, "Error: bpf_set_link_xdp_fd failed for interface %d\n",
              ifindex);
      return 1;
    } else {
      printf("Main BPF program attached to XDP on interface %d\n", ifindex);
    }
  }
  int quit = 0;
  int sig = 0;
  sigset_t signal_mask;
  sigemptyset(&signal_mask);
  sigaddset(&signal_mask, SIGINT);
  sigaddset(&signal_mask, SIGTERM);

  struct sigaction sa;
  sa.sa_handler = &signal_handler;
  sa.sa_flags = SA_RESTART;
  sigfillset(&sa.sa_mask);
  if (sigaction(SIGINT, &sa, NULL) == -1 || sigaction(SIGTERM, &sa, NULL) == -1) {
    perror("Error: could not set signal handler");
    exit(EXIT_FAILURE);
  }

  while (!quit) {
    err = sigwait(&signal_mask, &sig);
    if (err != 0) {
      fprintf(stderr, "Error: Failed to wait for signal\n");
      exit(EXIT_FAILURE);
    }

    switch (sig) {
      case SIGINT:
      case SIGTERM:
        printf("Signal received, exiting...\n");
        quit = 1;
        break;

      default:
        fprintf(stderr, "Unknown signal\n");
        break;
    }
  }

      if (unpin_map(map_filename) < 0) {
        perror("Error unpinning map");
        return 1;
    }

  return 0;
}
