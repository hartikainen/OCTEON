#include <stdio.h>
#include <string.h>
#include <math.h>

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
#include "cvmx-atomic.h"
#include "cvmx-log.h"
#include "cvmx-rng.h"
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

#define CORE_COUNT 32
#define WRITE_SIZE_MAX 4194304
#define WRITE_SIZE_MAX_POW ((int)log2(WRITE_SIZE_MAX))
#define WRITE_COUNT_MAX 4194304
#define WRITE_COUNT_MAX_POW ((int)log2(WRITE_COUNT_MAX))

CVMX_SHARED long dummy[WRITE_SIZE_MAX];
void memtest_main_loop(struct cvmx_coremask coremask) {
  uint64_t start_clock, end_clock;
  int i, ii, j, jj, c;
  long long clock_rate = (long long)cvmx_clock_get_rate(CVMX_CLOCK_CORE);
  long long print_timer = 0;
  int write_size, write_count;
  int corenum = cvmx_get_core_num();
  uint64_t delta[WRITE_SIZE_MAX_POW+1][WRITE_COUNT_MAX_POW+1];
  FILE *fp;
  char filename[strlen("memtest-x.log")];
  int random;

  sprintf(filename, "%s/memtest-%d.log", "./data", corenum);
  fp = fopen(filename, "w+");

  fprintf(fp, "size, count, core, time\n");
  random = (int)cvmx_rng_get_random32();

  COREMASK_BARRIER(coremask);
  for (i=0; i<=WRITE_SIZE_MAX_POW; i++) {
    write_size = (int)powl(2, (double)i);

    for (j=0; j<=WRITE_COUNT_MAX_POW; j++) {
      write_count = (int)powl(2, (double)j);

      COREMASK_BARRIER(coremask);
      start_clock = cvmx_clock_get_count(CVMX_CLOCK_CORE);
      for (ii=0; ii<i; ii++) {
        for (jj=0; jj<j; jj++) {
          cvmx_atomic_add64(&dummy[jj], random);
        }
      }
      end_clock = cvmx_clock_get_count(CVMX_CLOCK_CORE);
      delta[i][j] = end_clock - start_clock;

      COREMASK_BARRIER(coremask);
      for (c=0; c<CORE_COUNT; c++) {
        if (corenum == c)
          fprintf(fp, "%d, %d, %d, %f\n", write_size, write_count, corenum, (double)delta[i][j]);
        COREMASK_BARRIER(coremask);
      }
    }
  }
  fclose(fp);
  COREMASK_BARRIER(coremask);
  return;
}

int main(int argc, char *argv[]) {
  cvmx_sysinfo_t *sysinfo;
  struct cvmx_coremask coremask;

  cvmx_user_app_init();
  sysinfo = cvmx_sysinfo_get();
  cvmx_coremask_copy(&coremask, &sysinfo->core_mask);


  if (IS_INIT_CORE) {
    printf("Starting application\n\n");
    cvmx_rng_enable();
  }

  COREMASK_BARRIER(coremask);
  memtest_main_loop(coremask);

  return 0;
}
