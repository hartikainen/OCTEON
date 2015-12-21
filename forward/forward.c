#include <stdio.h>
#include <string.h>
#include <limits.h>

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


#define COREMASK_BARRIER(coremask) (cvmx_coremask_barrier_sync(&coremask))
#define IS_INIT_CORE (cvmx_is_init_core())

#define PKT_BUF_CNT 1080
#define SAMPLE_SIZE 1000

#include "app.config"

void application_main_loop(void) {
  cvmx_wqe_t* work;
  uint64_t start_clock, end_clock, delta;
  int packet_pool = (int)cvmx_fpa_get_packet_pool();
  int dummy, count;

  printf("Application main loop on core: %d\n", cvmx_get_core_num());

  while (1) {
    work = cvmx_pow_work_request_sync(CVMX_POW_WAIT);
    if (work == NULL) continue;

    start_clock = cvmx_clock_get_count(CVMX_CLOCK_CORE);
    dummy = INT_MAX;
    end_clock = cvmx_clock_get_count(CVMX_CLOCK_CORE);

    delta += end_clock - start_clock;
    count++;

    dummy = dummy;

    cvmx_helper_free_packet_data(work);
    cvmx_fpa_free(work, packet_pool, 0);

    if (count > SAMPLE_SIZE) {
      printf("delta, count, avg\n");
      printf("%lld, %d, %f\n", (unsigned long long)delta, count, (float)delta/(float)count);
      delta = 0;
      count = 0;
    }
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
