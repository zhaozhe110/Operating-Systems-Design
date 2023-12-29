#include <bpf.h>
#include <libbpf.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include "libiu.h"

#define BPF_SYSFS_ROOT "/sys/fs/bpf"
#define PINNED_MAP "/sys/fs/bpf/port_map"
#define EXE "./target/x86_64-unknown-linux-gnu/release/mp4-sample"

static int nr_cpus = 0;

struct bpf_progs_desc {
  char name[256];
  enum bpf_prog_type type;
  unsigned char pin;
  int map_prog_idx;
  struct bpf_program *prog;
};
struct PortRule {
    __u8 udp_action;
    __u8 tcp_action;
};
static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  if (level == LIBBPF_DEBUG || level == LIBBPF_INFO) {
    return vfprintf(stderr, format, args);
  }
  return 0;
}
void signal_handler(int signum) {
  if (signum == SIGINT || signum == SIGTERM) {
    if (unlink(PINNED_MAP) < 0) {
        perror("Error unpinning map");
    }
  }
}
int main(int argc, char *argv[]) {
  struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
  int base_fd, rx_prog_fd, tx_prog_fd, xdp_main_prog_fd;
  struct bpf_object_load_attr load_attr;
  struct bpf_program *rx_prog, *tx_prog;
  struct bpf_object *obj;
  int map_progs_xdp_fd;
  char filename[PATH_MAX];
  int err, prog_count;
  __u32 xdp_flags = 0;
  int *interfaces_idx;
  int ret = 0;

  int opt;
  int interface_count = 0;

  libbpf_set_print(libbpf_print_fn);
  iu_set_debug(1);  // enable debug info

  if(strcmp(argv[1], "add_rule") == 0){
      if (argc != 4) {
          fprintf(stderr, "Usage: %s add_rule <port> <protocol>\n", argv[0]);
          return 1;
      }

      uint32_t port = atoi(argv[2]);
      struct PortRule rule = { .udp_action = XDP_PASS, .tcp_action = XDP_PASS };

      if (strcmp(argv[3], "tcp") == 0) {
          rule.tcp_action = XDP_DROP;
      } else if (strcmp(argv[3], "udp") == 0) {
          rule.udp_action = XDP_DROP;
      } else {
          fprintf(stderr, "Invalid protocol. Use 'tcp' or 'udp'\n");
          return 1;
      }

      obj = iu_object__open(EXE);
      if (!obj) {
          fprintf(stderr, "Object could not be opened\n");
          return 1;
      }

      map_progs_xdp_fd = bpf_obj_get(PINNED_MAP);
      if (map_progs_xdp_fd < 0) {
          fprintf(stderr, "Error: bpf_obj_get failed\n");
          return 1;
      }

      int result = bpf_map_update_elem(map_progs_xdp_fd, &port, &rule, BPF_ANY);
      if (result) {
          perror("bpf_map_update_elem");
          return 1;
      } else {
          printf("Added rule for port %d\n", port);
      }

      return 0;

  }
    else{
    interface_count = argc - optind;
    if (interface_count <= 0) {
        fprintf(stderr, "Missing at least one required interface index\n");
        exit(EXIT_FAILURE);
    }

    interfaces_idx = calloc(sizeof(int), interface_count);
    if (interfaces_idx == NULL) {
        fprintf(stderr, "Error: failed to allocate memory\n");
        return 1;
    }

    for (int i = 0; i < interface_count && optind < argc; optind++, i++) {
        interfaces_idx[i] = atoi(argv[optind]);
    }
    nr_cpus = libbpf_num_possible_cpus();

    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit failed");
        return 1;
    }

    obj = iu_object__open(EXE);
    if (!obj) {
        fprintf(stderr, "Object could not be opened\n");
        exit(1);
    }

        map_progs_xdp_fd = bpf_object__find_map_fd_by_name(obj, "port_map");
    if (map_progs_xdp_fd < 0) {
      fprintf(stderr, "Error: bpf_object__find_map_fd_by_name failed\n");
      return 1;
    }


      if (bpf_obj_pin(map_progs_xdp_fd, PINNED_MAP) < 0) {
            perror("Error pinning map");
            return 1;
        }

    rx_prog = bpf_object__find_program_by_name(obj, "xdp_rx_filter");
    if (!rx_prog) {
        fprintf(stderr, "start not found\n");
        exit(1);
    }

    xdp_main_prog_fd = bpf_program__fd(rx_prog);
    if (xdp_main_prog_fd < 0) {
        fprintf(stderr, "Error: bpf_program__fd failed\n");
        return 1;
    }

    // xdp_flags |= XDP_FLAGS_DRV_MODE;
    xdp_flags |= XDP_FLAGS_SKB_MODE;
    for (int i = 0; i < interface_count; i++) {
        if (bpf_set_link_xdp_fd(interfaces_idx[i], xdp_main_prog_fd, xdp_flags) <
            0) {
        fprintf(stderr, "Error: bpf_set_link_xdp_fd failed for interface %d\n",
                interfaces_idx[i]);
        return 1;
        } else {
        printf("Main BPF program attached to XDP on interface %d\n",
                interfaces_idx[i]);
        }
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


    if (unlink(PINNED_MAP) < 0) {
        perror("Error unpinning map");
        return 1;
    }
  return ret;
}
