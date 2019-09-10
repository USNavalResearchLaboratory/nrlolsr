LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := nrlolsrd
LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/../../protolib/include \
	$(LOCAL_PATH)/../../common
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_C_INCLUDES)
LOCAL_STATIC_LIBRARIES := protolib

ifeq ($(APP_OPTIM),debug)
	LOCAL_CFLAGS += -DANDROID
endif
LOCAL_EXPORT_CFLAGS := $(LOCAL_CFLAGS)

LOCAL_SRC_FILES := \
	../../common/nrlolsr.cpp \
	../../common/olsr_packet_types.cpp \
	../../common/nbr_queue.cpp \
	../../common/nrlolsrApp.cpp

include $(BUILD_EXECUTABLE)

$(call import-module,protolib/makefiles/android/jni)
