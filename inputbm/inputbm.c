#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <inttypes.h>

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
//#define TIME_DROPS

void application_main_loop(void) {
  cvmx_wqe_t* work;
  int packet_pool = (int)cvmx_fpa_get_packet_pool();
  int corenum = cvmx_get_core_num();

  uint64_t start_clock, end_clock, delta;
  uint64_t work_fetch_got_work_T = 0, work_fetch_got_work_T2 = 0, got_work_N = 0;
  uint64_t work_fetch_no_work_T = 0, work_fetch_no_work_T2 = 0, no_work_N = 0;
  uint64_t data_drop_T = 0, data_drop_T2 = 0;
  uint64_t wqe_drop_T = 0, wqe_drop_T2 = 0;

  while (1) {
    /* Time the work fetch */
    start_clock = cvmx_clock_get_count(CVMX_CLOCK_CORE);

    work = cvmx_pow_work_request_sync(CVMX_POW_WAIT);

    end_clock = cvmx_clock_get_count(CVMX_CLOCK_CORE);
    delta = end_clock - start_clock;

    if (work == NULL) {
      if (got_work_N > 0) {
        work_fetch_no_work_T  += delta;
        work_fetch_no_work_T2 += delta * delta;
        no_work_N++;
      }
      continue;
    }

    work_fetch_got_work_T  += delta;
    work_fetch_got_work_T2 += delta * delta;
    got_work_N++;

#ifdef TIME_DROPS
    /* Time the packet data drop */
    start_clock = cvmx_clock_get_count(CVMX_CLOCK_CORE);

    cvmx_helper_free_packet_data(work);

    end_clock = cvmx_clock_get_count(CVMX_CLOCK_CORE);
    delta = end_clock - start_clock;

    data_drop_T  += delta;
    data_drop_T2 += delta * delta;

    /* Time the WQE drop */
    start_clock = cvmx_clock_get_count(CVMX_CLOCK_CORE);

    cvmx_fpa_free(work, packet_pool, 0);

    end_clock = cvmx_clock_get_count(CVMX_CLOCK_CORE);
    delta = end_clock - start_clock;

    wqe_drop_T  += delta;
    wqe_drop_T2 += delta * delta;

    if (got_work_N > SAMPLE_SIZE) {
      printf("%d, %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 " , %" PRIu64 ", %" PRIu64 "\n",
             corenum,
             work_fetch_got_work_T, work_fetch_got_work_T2, got_work_N,
             work_fetch_no_work_T, work_fetch_no_work_T2, no_work_N,
             data_drop_T, data_drop_T2,
             wqe_drop_T, wqe_drop_T2);
      return;
    }
#else
    cvmx_helper_free_packet_data(work);
    cvmx_fpa_free(work, packet_pool, 0);

    if (got_work_N > SAMPLE_SIZE) {
      printf("%d, %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 "\n",
             corenum,
             work_fetch_got_work_T, work_fetch_got_work_T2, got_work_N,
             work_fetch_no_work_T, work_fetch_no_work_T2, no_work_N);
      return;
    }
#endif
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

  if (IS_INIT_CORE) {
    printf("Starting application\n\n");
    printf("core, work_fetch_got_work_T, work_fetch_got_work_T2, got_work_N, work_fetch_no_work_T, work_fetch_no_work_T2, no_work_N, data_drop_T, data_drop_T2, wqe_drop_T, wqe_drop_T2\n");
  }

  application_main_loop();

  COREMASK_BARRIER(coremask);

  return result;
}
