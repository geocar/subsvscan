# normally you'll call this with make args...
# make common/lock.c
all: subsvscan
subsvscan: unix/subsvscan.c common/lock.c
