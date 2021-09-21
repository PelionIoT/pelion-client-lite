###########################################################################
#
#  Copyright (c) 2020, ARM Limited, All Rights Reserved
#  SPDX-License-Identifier: Apache-2.0
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
###########################################################################

#
# Use this file to import an mbed TLS release into mbed-OS as follows:
#
#   1) Set the MBED_TLS_RELEASE variable to the required mbed TLS release tag
#   2) make update
#   3) make
#   4) commit and push changes via git
#
# Use this file to execute Mbed TLS tests as follows:
#
#   1) Import mbed TLS files as described above
#   2) Run all Mbed TLS tests with command "make mbedtls-tests".
#      Individual test sets can be executed with commands "make unit-tests",
#      "module-test-compat" and "module-test-ssl-opt".
#

# Set the mbed TLS release to import (this can/should be edited before import)
MBED_TLS_RELEASE ?= baremetal
MBED_TLS_REPO_URL ?= git@github.com:PelionIoT/pelion-crypto.git

# Translate between mbed TLS namespace and mbed namespace
TARGET_PREFIX:=../
TARGET_MBEDTLS_SRC:=$(TARGET_PREFIX)src
TARGET_MBEDTLS_INC:=$(TARGET_PREFIX)inc/mbedtls
TARGET_MBEDTLS_INC_DIR:=$(TARGET_PREFIX)inc
TARGET_TINYCRYPT_SRC:=$(TARGET_PREFIX)tinycrypt
TARGET_TINYCRYPT_INC:=$(TARGET_PREFIX)inc/tinycrypt
TARGET_TESTS:=$(TARGET_PREFIX)TESTS
TARGET_TEST_PROGRAMS:=$(TARGET_PREFIX)programs
TARGET_TEST_FOLDER:=$(TARGET_PREFIX)tests
TARGET_TEST_SCRIPT:=$(TARGET_PREFIX)scripts

# mbed TLS source directory - hidden from mbed via TARGET_IGNORE
MBED_TLS_DIR:=TARGET_IGNORE/mbedtls

MBED_TLS_ROOT:=$(MBED_TLS_DIR)/
MBED_TLS_SRC:=$(MBED_TLS_DIR)/library/
MBED_TLS_API:=$(MBED_TLS_DIR)/include/mbedtls/
MBED_TLS_PROGRAMS:=$(MBED_TLS_DIR)/programs/
MBED_TLS_TESTS:=$(MBED_TLS_DIR)/tests/
MBED_TLS_SCRIPTS:=$(MBED_TLS_DIR)/scripts/
MBED_TLS_CONFIGS:=$(MBED_TLS_DIR)/configs/
MBED_TLS_INCLUDE:=$(MBED_TLS_DIR)/include/

MBED_TLS_TINYCRYPT_SRC:=$(MBED_TLS_DIR)/tinycrypt/
MBED_TLS_TINYCRYPT_API:=$(MBED_TLS_DIR)/include/tinycrypt/

MBED_TLS_GIT_CFG=$(MBED_TLS_DIR)/.git/config

.PHONY: all deploy deploy-tests rsync mbedtls clean update

all: mbedtls

mbedtls: deploy

rsync:
	#
	# Copying Mbed TLS
	rm -rf $(TARGET_MBEDTLS_SRC)
	rsync -a --exclude='*.txt' $(MBED_TLS_SRC) $(TARGET_MBEDTLS_SRC)
	#
	# Copying mbed TLS headers
	rm -rf $(TARGET_MBEDTLS_INC)
	mkdir -p $(TARGET_MBEDTLS_INC)
	rsync -a --delete $(MBED_TLS_API) $(TARGET_MBEDTLS_INC)
	#
	# Copying tinycrypt
	rm -rf $(TARGET_TINYCRYPT_SRC)
	rsync -a --exclude='*.txt' $(MBED_TLS_TINYCRYPT_SRC) $(TARGET_TINYCRYPT_SRC)
	#
	# Copying tinycrypt headers
	rm -rf $(TARGET_TINYCRYPT_INC)
	mkdir -p $(TARGET_TINYCRYPT_INC)
	rsync -a --delete $(MBED_TLS_TINYCRYPT_API) $(TARGET_TINYCRYPT_INC)
	#
	# Copying licenses
	cp $(MBED_TLS_DIR)/LICENSE $(TARGET_PREFIX)
	cp $(MBED_TLS_DIR)/apache-2.0.txt $(TARGET_PREFIX)
	#
	# Copy files related to unit and module tests
	# tests, programs, configs and scripts
	rm -rf  $(TARGET_TEST_FOLDER)
	mkdir -p  $(TARGET_TEST_FOLDER)
	rm -rf  $(TARGET_TEST_PROGRAMS)
	mkdir -p  $(TARGET_TEST_PROGRAMS)
	rm -rf  $(TARGET_TEST_SCRIPT)
	mkdir -p  $(TARGET_TEST_SCRIPT)
	rsync -a --delete $(MBED_TLS_TESTS) $(TARGET_TEST_FOLDER)
	rsync -a --delete $(MBED_TLS_PROGRAMS) $(TARGET_TEST_PROGRAMS)
	cp $(MBED_TLS_SCRIPTS)config.pl $(TARGET_TEST_SCRIPT)/config.pl
	cp $(MBED_TLS_SCRIPTS)output_env.sh $(TARGET_TEST_SCRIPT)/output_env.sh
	rm $(TARGET_TEST_FOLDER)/.gitignore
	rm $(TARGET_TEST_FOLDER)/data_files/.gitignore
	rm -rf $(TARGET_TEST_FOLDER)/.jenkins/

	# Makefiles
	cp $(MBED_TLS_ROOT)Makefile $(TARGET_PREFIX)
	cp $(MBED_TLS_SRC)Makefile $(TARGET_MBEDTLS_SRC)

	# Make a copy of original config.h for testing. Make it full config and add small adjustments
	cp $(MBED_TLS_API)config.h $(TARGET_MBEDTLS_INC)/test_config.h
	../scripts/config.pl -f $(TARGET_MBEDTLS_INC)/test_config.h full
	../scripts/config.pl -f $(TARGET_MBEDTLS_INC)/test_config.h unset MBEDTLS_MEMORY_BUFFER_ALLOC_C
	../scripts/config.pl -f $(TARGET_MBEDTLS_INC)/test_config.h unset MBEDTLS_MEMORY_DEBUG
	../scripts/config.pl -f $(TARGET_MBEDTLS_INC)/test_config.h unset MBEDTLS_MEMORY_BACKTRACE

deploy: rsync
	#
	# Adjusting the default mbed TLS config file to mbed purposes
	./adjust-config.sh $(MBED_TLS_DIR)/scripts/config.pl $(TARGET_MBEDTLS_INC)/config.h
	#
	# Copy and adjust the trimmed config that does not require entropy source
	cp $(MBED_TLS_DIR)/configs/config-no-entropy.h $(TARGET_MBEDTLS_INC)/.
	./adjust-no-entropy-config.sh $(MBED_TLS_DIR)/scripts/config.pl $(TARGET_MBEDTLS_INC)/config-no-entropy.h

deploy-tests: deploy
	#
	# Copying mbed TLS tests...
	rm -rf $(TARGET_TESTS)
	mkdir -p $(TARGET_TESTS)
	rsync -a --delete $(MBED_TLS_DIR)/tests/TESTS/ $(TARGET_TESTS)
	mkdir -p $(TARGET_TESTS)/host_tests
	cp $(MBED_TLS_DIR)/tests/scripts/mbedtls_test.py $(TARGET_TESTS)/host_tests/

make-test-build:
	# Compile tests
	make -C $(TARGET_TEST_FOLDER)
	make -C $(TARGET_TEST_PROGRAMS)

unit-tests: make-test-build
	# execute unit tests
	make test -C $(TARGET_TEST_FOLDER)

module-test-ssl-opt: make-test-build
	# execute module test: ssl-opt.sh
	cd $(TARGET_PREFIX) && ./tests/ssl-opt.sh -s

module-test-compat: make-test-build
	# execute module test: compat.sh
	cd $(TARGET_PREFIX) && ./tests/compat.sh

module-tests: module-test-compat module-test-ssl-opt

mbedtls-tests: unit-tests module-tests

update: $(MBED_TLS_GIT_CFG)  $(MBED_TLS_HA_GIT_CFG)
	#
	# Updating to the specified mbed TLS library version
	# (If it is not an initial checkout we will start with the repository
	# being in a detached head state)
	git -C $(MBED_TLS_DIR) fetch $(MBED_TLS_REPO_URL) $(MBED_TLS_RELEASE)
	#
	# Checking out the required release
	git -C $(MBED_TLS_DIR) checkout FETCH_HEAD
	#
	# Updating checked out version tag
	git -C $(MBED_TLS_DIR) describe --tags --abbrev=12 --dirty --always > $(TARGET_PREFIX)VERSION.txt

$(MBED_TLS_GIT_CFG):
	rm -rf $(MBED_TLS_DIR)
	git clone $(MBED_TLS_REPO_URL) $(MBED_TLS_DIR)

clean:
	rm -f $(TARGET_PREFIX)LICENSE
	rm -f $(TARGET_PREFIX)apache-2.0.txt
	rm -f $(TARGET_PREFIX)VERSION.txt
	rm -f $(TARGET_PREFIX)AUTHORS.txt
	rm -rf $(TARGET_MBEDTLS_SRC)
	rm -rf $(TARGET_MBEDTLS_INC)
	rm -rf $(TARGET_TINYCRYPT_SRC)
	rm -rf $(TARGET_TINYCRYPT_INC)
	rm -rf $(MBED_TLS_DIR)
