ACLOCAL_AMFLAGS = -I m4
AM_CXXFLAGS = $(FW_INCLUDE) $(TSK_INCLUDE) -Wall

lib_LTLIBRARIES = libtskInterestingFilesModule.la
libtskInterestingFilesModule_la_SOURCES = InterestingFilesModule.cpp
libtskInterestingFilesModule_la_LIBADD = $(FW_LIBS)

nobase_dist_data_DATA = tsk/InterestingFilesModule/*

bin_PROGRAMS = maybe_copy_configs

MODULE_CONFIG_DIR = $(RUNTIME_MODULES_CONFIG_DIR)/InterestingFilesModule

maybe_copy_configs:
	if test "$(FW_LIBS)" != ""; then \
		mkdir -p $(MODULE_CONFIG_DIR); \
		(cd $(MODULE_CONFIG_DIR); ln -sf $(MODULES_ROOT_DIR)/c_InterestingFilesModule/tsk/InterestingFilesModule/interesting_files.xml .); \
	fi
