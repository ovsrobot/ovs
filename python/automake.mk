ovstest_pyfiles = \
	python/ovstest/__init__.py \
	python/ovstest/args.py \
	python/ovstest/rpcserver.py \
	python/ovstest/tcp.py \
	python/ovstest/tests.py \
	python/ovstest/udp.py \
	python/ovstest/util.py \
	python/ovstest/vswitch.py

ovs_pyfiles = \
	python/ovs/__init__.py \
	python/ovs/compat/__init__.py \
	python/ovs/compat/sortedcontainers/__init__.py \
	python/ovs/compat/sortedcontainers/sortedlist.py \
	python/ovs/compat/sortedcontainers/sorteddict.py \
	python/ovs/compat/sortedcontainers/sortedset.py \
	python/ovs/daemon.py \
	python/ovs/fcntl_win.py \
	python/ovs/db/__init__.py \
	python/ovs/db/custom_index.py \
	python/ovs/db/data.py \
	python/ovs/db/error.py \
	python/ovs/db/idl.py \
	python/ovs/db/parser.py \
	python/ovs/db/schema.py \
	python/ovs/db/types.py \
	python/ovs/fatal_signal.py \
	python/ovs/json.py \
	python/ovs/jsonrpc.py \
	python/ovs/ovsuuid.py \
	python/ovs/poller.py \
	python/ovs/process.py \
	python/ovs/reconnect.py \
	python/ovs/socket_util.py \
	python/ovs/stream.py \
	python/ovs/timeval.py \
	python/ovs/unixctl/__init__.py \
	python/ovs/unixctl/client.py \
	python/ovs/unixctl/server.py \
	python/ovs/util.py \
	python/ovs/version.py \
	python/ovs/vlog.py \
	python/ovs/winutils.py \
	python/ovs/flows/__init__.py \
	python/ovs/flows/decoders.py \
	python/ovs/flows/kv.py \
	python/ovs/flows/list.py \
	python/ovs/flows/flow.py \
	python/ovs/flows/ofp.py \
	python/ovs/flows/ofp_act.py \
	python/ovs/flows/odp.py \
	python/ovs/flows/filter.py \
	python/ovs/flows/deps.py

ovs_tests = \
	python/ovs/tests/test_kv.py \
	python/ovs/tests/test_list.py \
	python/ovs/tests/test_ofp.py \
	python/ovs/tests/test_odp.py \
	python/ovs/tests/test_filter.py


# These python files are used at build time but not runtime,
# so they are not installed.
EXTRA_DIST += \
	python/build/__init__.py \
	python/build/nroff.py \
	python/build/soutil.py \
	python/build/extract_ofp_fields.py \
	python/build/flow-parse-deps.py

# PyPI support.
EXTRA_DIST += \
	python/ovs/compat/sortedcontainers/LICENSE \
	python/README.rst \
	python/setup.py

# C extension support.
EXTRA_DIST += python/ovs/_json.c

PYFILES = $(ovs_pyfiles) python/ovs/dirs.py $(ovstest_pyfiles) $(ovs_tests)

EXTRA_DIST += $(PYFILES)
PYCOV_CLEAN_FILES += $(PYFILES:.py=.py,cover)

FLAKE8_PYFILES += \
	$(filter-out python/ovs/compat/% python/ovs/dirs.py,$(PYFILES)) \
	python/setup.py \
	python/build/__init__.py \
	python/build/nroff.py \
	python/ovs/dirs.py.template

nobase_pkgdata_DATA = $(ovs_pyfiles) $(ovstest_pyfiles)
ovs-install-data-local:
	$(MKDIR_P) python/ovs
	sed \
		-e '/^##/d' \
		-e 's,[@]pkgdatadir[@],$(pkgdatadir),g' \
		-e 's,[@]RUNDIR[@],$(RUNDIR),g' \
		-e 's,[@]LOGDIR[@],$(LOGDIR),g' \
		-e 's,[@]bindir[@],$(bindir),g' \
		-e 's,[@]sysconfdir[@],$(sysconfdir),g' \
		-e 's,[@]DBDIR[@],$(DBDIR),g' \
		< $(srcdir)/python/ovs/dirs.py.template \
		> python/ovs/dirs.py.tmp
	$(MKDIR_P) $(DESTDIR)$(pkgdatadir)/python/ovs
	$(INSTALL_DATA) python/ovs/dirs.py.tmp $(DESTDIR)$(pkgdatadir)/python/ovs/dirs.py
	rm python/ovs/dirs.py.tmp

python-sdist: $(srcdir)/python/ovs/version.py $(ovs_pyfiles) python/ovs/dirs.py
	(cd python/ && $(PYTHON3) setup.py sdist)

pypi-upload: $(srcdir)/python/ovs/version.py $(ovs_pyfiles) python/ovs/dirs.py
	(cd python/ && $(PYTHON3) setup.py sdist upload)
install-data-local: ovs-install-data-local

UNINSTALL_LOCAL += ovs-uninstall-local
ovs-uninstall-local:
	rm -f $(DESTDIR)$(pkgdatadir)/python/ovs/dirs.py

ALL_LOCAL += $(srcdir)/python/ovs/version.py
$(srcdir)/python/ovs/version.py: config.status
	$(AM_V_GEN)$(ro_shell) > $(@F).tmp && \
	echo 'VERSION = "$(VERSION)"' >> $(@F).tmp && \
	if cmp -s $(@F).tmp $@; then touch $@; rm $(@F).tmp; else mv $(@F).tmp $@; fi

ALL_LOCAL += $(srcdir)/python/ovs/dirs.py
$(srcdir)/python/ovs/dirs.py: python/ovs/dirs.py.template
	$(AM_V_GEN)sed \
		-e '/^##/d' \
		-e 's,[@]pkgdatadir[@],$(pkgdatadir),g' \
		-e 's,[@]RUNDIR[@],$(RUNDIR),g' \
		-e 's,[@]LOGDIR[@],$(LOGDIR),g' \
		-e 's,[@]bindir[@],$(bindir),g' \
		-e 's,[@]sysconfdir[@],$(sysconfdir),g' \
		-e 's,[@]DBDIR[@],$(sysconfdir)/openvswitch,g' \
		< $? > $@.tmp && \
	mv $@.tmp $@
EXTRA_DIST += python/ovs/dirs.py.template
CLEANFILES += python/ovs/dirs.py

$(srcdir)/python/ovs/flows/ofp_fields.py: $(srcdir)/build-aux/gen_ofp_field_decoders include/openvswitch/meta-flow.h
	$(AM_V_GEN)$(run_python) $< $(srcdir)/include/openvswitch/meta-flow.h > $@.tmp
	$(AM_V_at)mv $@.tmp $@
EXTRA_DIST += python/ovs/flows/ofp_fields.py
CLEANFILES += python/ovs/flows/ofp_fields.py

ALL_LOCAL += flowparse-deps-check
DEPS = $(shell $(AM_V_GEN)$(run_python) $(srcdir)/python/build/flow-parse-deps.py list)
flowparse-deps-check: $(srcdir)/python/build/flow-parse-deps.py $(DEPS)
	echo $(DEPS)
	$(AM_V_GEN)$(run_python) $(srcdir)/python/build/flow-parse-deps.py check
	touch $@
CLEANFILES += flowparse-deps-check

if HAVE_PYTEST
ALL_LOCAL += pytest-check
pytest-check: $(ovs_pyfiles) $(ovs_tests)
	$(AM_V_GEN)$(run_python) -m pytest $(srcdir)/python/ovs
	touch $@
CLEANFILES += pytest-check

endif
