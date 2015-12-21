ifndef OCTEON_ROOT
OCTEON_ROOT = ../../..
endif

MODEL=${OCTEON_MODEL}
OCTEON_LDFLAGS_GLOBAL_ADD = -lm
CFLAGS_LOCAL = -g -O0 -W -Wall -Wno-unused-parameter -DSINGLE_PORT_SIM -DENABLE_USING_CONFIG_STRING

all: application-target

include $(OCTEON_ROOT)/common.mk
dir := $(OCTEON_ROOT)/executive
include $(dir)/cvmx.mk
DEPS = $(OBJS:%.o=%.d)

TARGET = inputbm$(PREFIX)
OBJS =  $(OBJ_DIR)/inputbm.o

include $(OCTEON_ROOT)/application.mk

clean:
	rm -f $(TARGET)
	rm -f $(CLEAN_LIST) $(OBJS) $(DEPS)
	rm -f $(CVMX_CONFIG)

clobber: clean
	rm -rf $(OBJ_DIR)
