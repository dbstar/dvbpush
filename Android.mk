# Copyright (C) 2009 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := dvbpush
LOCAL_ARM_MODE := arm
LOCAL_MODULE_TAGS := optional
LOCAL_PRELINK_MODULE := false

LOCAL_SRC_FILES += \
	src/mid_push.c \
	src/common.c \
	src/multicast.c \
	src/main.c \
	src/xmlparser.c \
	src/sqlite.c \
	src/porting.c

LOCAL_CFLAGS += -Llib

LOCAL_CFLAGS += -W -Wall

LOCAL_C_INCLUDES += $(LOCAL_PATH)/include

#LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/dvb

LOCAL_STATIC_LIBRARIES += libpush
LOCAL_SHARED_LIBRARIES += libc libdl liblog libsqlite libxml2 libiconv

#LOCAL_LDLIBS := $(LOCAL_PATH)/lib/libpush.a
#LOCAL_LDLIBS += $(LOCAL_PATH)/lib/libxml2.so
#LOCAL_LDLIBS += $(LOCAL_PATH)/lib/libiconv.so
#LOCAL_LDLIBS += $(LOCAL_PATH)/lib/libsqlite3.so

include $(BUILD_EXECUTABLE)
