/*
 * Copyright (c) 2015 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef PROTOMAN_CONFIG_H
#define PROTOMAN_CONFIG_H


/*! \file protoman_config.h
* \brief File defining all system build time configuration used by protoman.
*/

/**
 * \def PROTOMAN_SECURITY_ENABLE_CERTIFICATE
 *
 * \brief Enables x509 certificate handling specific
 * code.
 */
//#undef PROTOMAN_SECURITY_ENABLE_CERTIFICATE

/**
 * \def PROTOMAN_SECURITY_ENABLE_PSK
 *
 * \brief Enables PSK handling specific code.
 */
//#undef PROTOMAN_SECURITY_ENABLE_PSK

/**
 * \def PROTOMAN_SECURITY_ENABLE_CERTIFICATE_HOSTNAME_CHECK
 *
 * \brief Enables server certificate CN check.
 */
//#undef PROTOMAN_SECURITY_ENABLE_CERTIFICATE_HOSTNAME_CHECK

/**
 * \def PROTOMAN_INTERRUPT_PRINT
 *
 * \brief Enables additional debug prints from interrupt context.
 */
//#undef PROTOMAN_INTERRUPT_PRINT

/**
 * \def PROTOMAN_ERROR_STRING
 *
 * \brief Enables verbose error translation for various components.
 */
//#undef PROTOMAN_ERROR_STRING

/**
 * \def PROTOMAN_VERBOSE_POINTERS
 *
 * \brief Enables verbose pointer printing.
 */
//#undef PROTOMAN_VERBOSE_POINTERS

/**
 * \def PROTOMAN_VERBOSE
 *
 * \brief Enables verbose debug messages.
 */
//#undef PROTOMAN_VERBOSE

/**
 * \def PROTOMAN_OFFLOAD_TLS
 *
 * \brief Enables external secure socket implementation.
 * Can be used only in TCP mode. If used there is no need for separate mbedTLS layer.
 */
//#undef PROTOMAN_OFFLOAD_TLS

/**
 * \def PROTOMAN_USE_SSL_SESSION_RESUME
 *
 * \brief Enables SSL session resume feature.
 */
//#undef PROTOMAN_USE_SSL_SESSION_RESUME

/* For Doxygen, make all config variables visible */
#if __DOXYGEN__
#define PROTOMAN_SECURITY_ENABLE_CERTIFICATE
#define PROTOMAN_SECURITY_ENABLE_PSK
#define PROTOMAN_SECURITY_ENABLE_CERTIFICATE_HOSTNAME_CHECK
#define PROTOMAN_INTERRUPT_PRINT
#define PROTOMAN_ERROR_STRING
#define PROTOMAN_VERBOSE_POINTERS
#define PROTOMAN_VERBOSE
#define PROTOMAN_OFFLOAD_TLS
#define PROTOMAN_USE_SSL_SESSION_RESUME
#endif



#ifdef MBED_CLIENT_USER_CONFIG_FILE
#include MBED_CLIENT_USER_CONFIG_FILE
#endif

#ifdef MBED_CLOUD_CLIENT_USER_CONFIG_FILE
#include MBED_CLOUD_CLIENT_USER_CONFIG_FILE
#endif

#ifdef PROTOMAN_USER_CONFIG_FILE
#include PROTOMAN_USER_CONFIG_FILE
#endif

#endif // PROTOMAN_CONFIG_H

