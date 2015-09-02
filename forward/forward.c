#include <stdio.h>
#include <string.h>

#include "cvmx-config.h"
#include "cvmx.h"
#include "cvmx-spinlock.h"
#include "cvmx-fpa.h"
#include "cvmx-ilk.h"
#include "cvmx-pip.h"
#include "cvmx-ipd.h"
#include "cvmx-pko.h"
#include "cvmx-dfa.h"
#include "cvmx-pow.h"
#include "cvmx-sysinfo.h"
#include "cvmx-coremask.h"
#include "cvmx-bootmem.h"
#include "cvmx-helper.h"
#include "cvmx-app-hotplug.h"
#include "cvmx-helper-cfg.h"
#include "cvmx-srio.h"
#include "cvmx-config-parse.h"


// #define FAU_EXAMPLE     ((cvmx_fau_reg_64_t)(CVMX_FAU_REG_AVAIL_BASE + 0))
#define COREMASK_BARRIER(coremask) (cvmx_coremask_barrier_sync(&coremask))
#define IS_INIT_CORE (cvmx_is_init_core())

CVMX_SHARED long long arrive_clock;
CVMX_SHARED long long departure_clock;

#define PKT_BUF_CNT 2000

#include "app.config"

//#define DUMP_PACKETS 1

static inline void forward_to_mac_addr(uint64_t pkt_ptr, char* dest) {
  // destination first 6 bytes, source next 6 bytes
  uint16_t s;
  uint32_t w;
  int bytes[6];

  sscanf(dest, "%x:%x:%x:%x:%x:%x",
         &bytes[0], &bytes[1], &bytes[2],
         &bytes[3], &bytes[4], &bytes[5]);

  s = (bytes[0] << 8)  | (bytes[1] << 0);
  w = (bytes[2] << 24) | (bytes[3] << 16) | (bytes[4] << 8) | (bytes[5]);

  // move the old destination (e.g. our own mac) to source
  *(uint16_t*) (pkt_ptr+6) = *(uint16_t*) (pkt_ptr);
  *(uint32_t*) (pkt_ptr+8) = *(uint32_t*) (pkt_ptr+2);

  // change the destination to dest
  *(uint16_t*) (pkt_ptr)   = s;
  *(uint32_t*) (pkt_ptr+2) = w;
}

static inline void swap_mac_addr(uint64_t pkt_ptr) {
  uint16_t s;
  uint32_t w;

  s = *(uint16_t*)(pkt_ptr+0);
  w = *(uint32_t*)(pkt_ptr+2);

  *(uint16_t*)(pkt_ptr+0) = *(uint16_t*)(pkt_ptr+6);
  *(uint32_t*)(pkt_ptr+2) = *(uint32_t*)(pkt_ptr+8);
  *(uint16_t*)(pkt_ptr+6) = s;
  *(uint32_t*)(pkt_ptr+8) = w;
}

void application_main_loop(void) {
  cvmx_wqe_t *    work;
  uint64_t        port;
  cvmx_buf_ptr_t  packet_ptr;
  cvmx_pko_command_word0_t pko_command;
  int queue, ret, pko_port;
  int packet_pool = (int)cvmx_fpa_get_packet_pool();
  int wqe_pool = (int)cvmx_fpa_get_wqe_pool();
  int packet_pool_size = cvmx_fpa_get_packet_pool_block_size();
  int wqe_len;
  long long counter = 0;

  printf("Application main loop on core: %d\n", cvmx_get_core_num());

  pko_port = -1;

  // Build a PKO pointer to this packet
  pko_command.u64 = 0;

  while (1) {
    work = cvmx_pow_work_request_sync(CVMX_POW_WAIT);
    if (work == NULL) {
      continue;
    }

    arrive_clock = cvmx_clock_get_count(CVMX_CLOCK_CORE);

    wqe_len = cvmx_wqe_get_len(work);
    port = cvmx_wqe_get_port(work);

    if (cvmx_unlikely(work->word2.snoip.rcv_error)) {
      printf("Dropped packet!\n");
      cvmx_helper_free_packet_data(work);
      cvmx_fpa_free(work, packet_pool, 0);

      continue;
    }

#ifdef DUMP_PACKETS
    printf("Packet data:\n");
    cvmx_helper_dump_packet(work);
#endif

    // PKO port differs from IPD port
    pko_port = cvmx_helper_cfg_ipd2pko_port_base(port);

    queue = cvmx_pko_get_base_queue_pkoid(pko_port);
    queue += (cvmx_get_core_num() % cvmx_pko_get_num_queues_pkoid(pko_port));

    cvmx_pko_send_packet_prepare(port, queue, CVMX_PKO_LOCK_ATOMIC_TAG);

    // bufs == 0: packet fits entirely in to WQE
    if (work->word2.s.bufs == 0) {
      pko_command.s.total_bytes = wqe_len;
      pko_command.s.segs = 1;
      packet_ptr.u64 = 0;
      packet_ptr.s.pool = packet_pool;
      packet_ptr.s.size = packet_pool_size;

      packet_ptr.s.addr = cvmx_ptr_to_phys(work->packet_data);
      if (cvmx_likely(!work->word2.s.not_IP)) {
        /* The beginning of the packet moves for IP packets */
        // not v6
        if (work->word2.s.is_v6)
          packet_ptr.s.addr += 2;
        else
          packet_ptr.s.addr += 6;
      }
    } else {
      pko_command.s.total_bytes = wqe_len;
      pko_command.s.segs = work->word2.s.bufs;
      packet_ptr = work->packet_ptr;
    }

    swap_mac_addr((uint64_t)cvmx_phys_to_ptr((uint64_t)packet_ptr.s.addr));

    departure_clock = cvmx_clock_get_count(CVMX_CLOCK_CORE);

    // cvmx_send_packet_prepare needs to be called before this
    // waits for the tag switch to complete
    ret = cvmx_pko_send_packet_finish_pkoid(pko_port, queue,
                                            pko_command, packet_ptr, CVMX_PKO_LOCK_ATOMIC_TAG);

    if (ret != CVMX_PKO_SUCCESS) {
      printf("Failed to send packet!\n");
      cvmx_helper_free_packet_data(work);
    }

    cvmx_fpa_free(work, wqe_pool, 0);
  }
}

static int application_init(int num_pkt_buf) {
  int result;
  cvmx_ipd_ctl_status_t ipd_ctl_status;

  printf("SDK Version: %s\n", cvmx_helper_get_version());

  if (cvmx_helper_initialize_fpa(num_pkt_buf, num_pkt_buf, CVMX_PKO_MAX_OUTPUT_QUEUES * 4, 0, 0))
    return -1;

  if (cvmx_helper_initialize_sso(num_pkt_buf))
    return -1;

  printf("Enabling CVMX_IPD_CTL_STATUS[NO_WPTR]\n");
  ipd_ctl_status.u64 = cvmx_read_csr(CVMX_IPD_CTL_STATUS);
  ipd_ctl_status.s.no_wptr = 1;
  cvmx_write_csr(CVMX_IPD_CTL_STATUS, ipd_ctl_status.u64);

  cvmx_helper_cfg_opt_set(CVMX_HELPER_CFG_OPT_USE_DWB, 0);
  result = cvmx_helper_initialize_packet_io_global();

  cvmx_helper_setup_red(num_pkt_buf/4, num_pkt_buf/8);

  cvmx_write_csr(CVMX_PIP_IP_OFFSET, 2);
  cvmx_helper_cfg_set_jabber_and_frame_max();
  cvmx_helper_cfg_store_short_packets_in_wqe();

  // Initialize the FAU registers.
  //cvmx_fau_atomic_write64(FAU_EXAMPLE, 0);

  return result;
}

int main(int argc, char *argv[]) {
  cvmx_sysinfo_t *sysinfo;
  struct cvmx_coremask coremask;
  int result = 0;

  if (IS_INIT_CORE) {
    cvmx_dprintf("Using config string \n");
    cvmx_set_app_config_str(app_config_str);
  }

  cvmx_user_app_init();
  sysinfo = cvmx_sysinfo_get();
  cvmx_coremask_copy(&coremask, &sysinfo->core_mask);

  // Use only the initial core for the boot inits
  if (IS_INIT_CORE) {
    if ((result = application_init(PKT_BUF_CNT)) != 0) {
      printf("Initialization failed.\n");
      return result;
    }
  }

  COREMASK_BARRIER(coremask);

  cvmx_helper_initialize_packet_io_local();

  COREMASK_BARRIER(coremask);

  if (IS_INIT_CORE) printf("Starting application\n\n");

  application_main_loop();

  COREMASK_BARRIER(coremask);

  return result;
}
