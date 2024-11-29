#
# This file is the cavp-test recipe.
#

SUMMARY = "Simple cavp-test application"
SECTION = "PETALINUX/apps"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

SRC_URI = "file://cavp-test.c \
	 file://SHA256ShortMsg.h \
	 file://SHA256LongMsg.h \
	   file://Makefile \
		  "

S = "${WORKDIR}"

do_compile() {
	     oe_runmake
}

do_install() {
	     install -d ${D}${bindir}
	     install -m 0755 cavp-test ${D}${bindir}		 
}


FILES_${PN} += "/home/petalinux"