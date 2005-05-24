inherit eutils

DESCRIPTION="ICMP Domain Name utilities"
HOMEPAGE="http://www.dolda2000.com/~fredrik/icmp-dn/"
SRC_URI="http://www.dolda2000.com/~fredrik/icmp-dn/${P}.tar.gz"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="x86"
IUSE=""

DEPEND=""

src_unpack() {
    unpack ${A}
    cd ${S}
}

src_compile() {
    econf --sysconfdir=/etc \
	  --libdir=/etc || die "Configuration failed"
    emake || die "Make failed"
}

src_install() {
    make install DESTDIR=${D} || die "Install failed"
    dodoc AUTHORS ChangeLog COPYING INSTALL NEWS README
}

pkg_postinst() {
    einfo
    einfo "To use the ICMP nameswitch module, add \"icmp\""
    einfo "to the \"hosts\" line in your /etc/nsswitch.conf"
    einfo
    ebeep 3
}
