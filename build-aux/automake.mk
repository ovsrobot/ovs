EXTRA_DIST += \
	build-aux/build/__init__.py \
	build-aux/build/extract_ofp_fields.py \
	build-aux/build/nroff.py \
	build-aux/build/soutil.py \
	build-aux/calculate-schema-cksum \
	build-aux/cccl \
	build-aux/cksum-schema-check \
	build-aux/dist-docs \
	build-aux/dpdkstrip.py \
	build-aux/generate-dhparams-c \
	build-aux/gen_ofp_field_decoders \
	build-aux/initial-tab-allowed-files \
	build-aux/sodepends.py \
	build-aux/soexpand.py \
	build-aux/text2c \
	build-aux/xml2nroff

FLAKE8_PYFILES += \
    build-aux/build/__init__.py \
    build-aux/build/extract_ofp_fields.py \
    build-aux/build/nroff.py \
    build-aux/build/soutil.py \
    build-aux/dpdkstrip.py \
    build-aux/gen_ofp_field_decoders \
    build-aux/sodepends.py \
    build-aux/soexpand.py \
    build-aux/xml2nroff
