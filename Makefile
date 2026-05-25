TARGET := iphone:clang:latest:14.0
INSTALL_TARGET_PROCESSES = AI_Video_Maker

ARCHS = arm64 arm64e

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = AIVideoUnlock

AIVideoUnlock_FILES = Tweak.x
AIVideoUnlock_CFLAGS = -fobjc-arc -Wno-unused-variable
AIVideoUnlock_FRAMEWORKS = Foundation UIKit StoreKit Security
AIVideoUnlock_PRIVATE_FRAMEWORKS =
AIVideoUnlock_LIBRARIES =

include $(THEOS_MAKE_PATH)/tweak.mk
