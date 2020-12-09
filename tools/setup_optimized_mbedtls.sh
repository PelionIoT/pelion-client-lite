#!/bin/bash
#
# Copyright (c) 2020 ARM Limited. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an AS IS BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

if [ ! -d "../mbedtls" ]
then
    cd ..
    MBEDTLS_HASH="858e4325d2eb55274950e9335d0c08a1326069c2"
    git clone https://github.com/ARMmbed/mbedtls.git 
    cd mbedtls
    git checkout "$MBEDTLS_HASH"
    cp -r ../tools/importer/ .
    cd importer
    make update
    make
    cd ..
    rm -rf library include programs
    cd ..
    echo "Making a backup of application .mbedignore file for cleanup"
    cp ../.mbedignore ../.mbedignore-application-backup-baremetal
    echo "Appending application .mbedignore file with baremetal TLS configurations"
    cat tools/.baremetal_mbedignore >> ../.mbedignore
    echo "optimized mbedtls is ready for mbed-os build..."
else
    echo "mbedtls is already cloned..."
fi
