#*******************************************************************************
#   Ledger Blue
#   (c) 2016 Ledger
#   Modified by the contributors to the Elastos Ledger app, 2018 to 2026
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#*******************************************************************************

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.target

########################################
#        Mandatory configuration       #
########################################
APPNAME = "Elastos"

APPVERSION_M = 1
APPVERSION_N = 2
APPVERSION_P = 0
APPVERSION = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"

APP_SOURCE_PATH += src

ICON_NANOS = icons/app_elastos_16px.gif
ICON_NANOX = icons/app_elastos_14px.gif
ICON_NANOSP = icons/app_elastos_14px.gif

CURVE_APP_LOAD_PARAMS = secp256r1
PATH_APP_LOAD_PARAMS = "44'/2305'"

VARIANT_PARAM = COIN
VARIANT_VALUES = elastos

########################################
#     Application custom permissions   #
########################################
# None. Nano X gets the settings permission from ENABLE_BLUETOOTH, which Bluetooth requires.

########################################
# Application communication interfaces #
########################################
# Essentials reaches the Nano X over Bluetooth.
ENABLE_BLUETOOTH = 1

########################################
#         NBGL custom features         #
########################################

########################################
#          Features enablers           #
########################################
# Only the Nano S SDK checks this canary below the stack; Nano X and Nano S Plus rely on the stack
# protector below.
DEFINES += HAVE_BOLOS_APP_STACK_CANARY
# The Nano S SDK's own app_metadata.c fails Werror under recent clang; app sources are clean.
ifeq ($(TARGET_NAME),TARGET_NANOS)
CFLAGS += -Wno-error=unterminated-string-initialization
endif
# Nano S: fail the link if globals leave less stack than this (SDK default 1,024). Sign needs about
# 1,516 bytes; tests/host/check_stack_depth.py checks that path's frames in CI.
ifeq ($(TARGET_NAME),TARGET_NANOS)
APP_STACK_MIN_SIZE = 1600
endif
# Nano X and Nano S Plus: src/ui.c wraps element drawing, so a review step counts as drawn only if
# every element was.
ifneq ($(TARGET_NAME),TARGET_NANOS)
LDFLAGS += -Wl,--wrap=io_seph_ux_display_bagl_element
endif

########################################
#        Stack protection features     #
########################################
# Nano X and Nano S Plus only; catches stack buffer overruns, not stack depth.
ENABLE_STACK_PROTECTOR = 1

########################################
#          Features disablers          #
########################################
# The app has its own main loop and I/O handlers (src/main.c).
DISABLE_STANDARD_APP_FILES = 1
DISABLE_STANDARD_APP_SYNC_RAPDU = 1
# No U2F transport: no Elastos client uses it.
DISABLE_STANDARD_U2F = 1
# Nano S uses UX_DISPLAY; Nano X and Nano S Plus get the flow engine from the SDK anyway.
DISABLE_STANDARD_BAGL_UX_FLOW = 1

include $(BOLOS_SDK)/Makefile.standard_app
