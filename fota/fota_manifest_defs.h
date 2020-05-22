// ----------------------------------------------------------------------------
// Copyright 2018-2019 ARM Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

#ifndef __FOTA_MANIFEST_DEFS_H_
#define __FOTA_MANIFEST_DEFS_H_

#include "fota/fota_base.h"

#ifndef FOTA_MANIFEST_SCHEMA_VERSION
#define FOTA_MANIFEST_SCHEMA_VERSION        3
#endif

#ifndef FOTA_MANIFEST_URI_SIZE
#define FOTA_MANIFEST_URI_SIZE            256
#endif

#ifndef FOTA_MANIFEST_VENDOR_DATA_SIZE
#define FOTA_MANIFEST_VENDOR_DATA_SIZE    128
#endif

#define FOTA_MANIFEST_PAYLOAD_FORMAT_RAW    1
#define FOTA_MANIFEST_PAYLOAD_FORMAT_DELTA  5

#ifndef FOTA_MANIFEST_MAX_SIZE
#define FOTA_MANIFEST_MAX_SIZE           512
#endif

#ifndef FOTA_CERT_MAX_SIZE
#define FOTA_CERT_MAX_SIZE 600
#endif

#endif // __FOTA_MANIFEST_DEFS_H_
