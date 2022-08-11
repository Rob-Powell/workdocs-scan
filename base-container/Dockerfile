FROM public.ecr.aws/lambda/python:3.9

# Set up working directories
RUN mkdir -p /opt/app
RUN mkdir -p /opt/app/bin/
RUN mkdir -p /opt/app/lib/

WORKDIR /opt/app

# Install packages
RUN yum update -y
RUN yum install -y cpio python3-pip yum-utils zip unzip less
RUN yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm

# Download libraries we need to run in lambda
WORKDIR /tmp
RUN yumdownloader -x \*i686 --archlist=x86_64 clamav clamav-lib clamav-update json-c pcre2 libprelude gnutls libtasn1 nettle libtool-ltdl libxml2 libcurl libnghttp2 libidn2 libssh2 openldap libffi krb5-libs keyutils-libs libunistring cyrus-sasl-lib nss nspr libselinux openssl-libs libcrypt
RUN rpm2cpio clamav-0*.rpm | cpio -idmv
RUN rpm2cpio clamav-lib*.rpm | cpio -idmv
RUN rpm2cpio clamav-update*.rpm | cpio -idmv
RUN rpm2cpio json-c*.rpm | cpio -idmv
RUN rpm2cpio pcre*.rpm | cpio -idmv
RUN rpm2cpio gnutls* | cpio -idmv
RUN rpm2cpio nettle* | cpio -idmv
RUN rpm2cpio libtool-ltdl* | cpio -idmv
RUN rpm2cpio libxml2* | cpio -idmv
RUN rpm2cpio libcurl* | cpio -idmv
RUN rpm2cpio libprelude* | cpio -idmv
RUN rpm2cpio libnghttp2* | cpio -idmv
RUN rpm2cpio libidn2* | cpio -idmv
RUN rpm2cpio libssh2* | cpio -idmv
RUN rpm2cpio openldap* | cpio -idmv
RUN rpm2cpio libffi* | cpio -idmv
RUN rpm2cpio krb5-libs* | cpio -idmv
RUN rpm2cpio keyutils-libs* | cpio -idmv
RUN rpm2cpio libunistring* | cpio -idmv
RUN rpm2cpio cyrus-sasl-lib* | cpio -idmv
RUN rpm2cpio nss* | cpio -idmv
RUN rpm2cpio nspr* | cpio -idmv
RUN rpm2cpio libselinux* | cpio -idmv
RUN rpm2cpio openssl-libs* | cpio -idmv
RUN rpm2cpio libcrypt* | cpio -idmv
RUN rpm2cpio *.rpm | cpio -idmv
RUN rpm2cpio libtasn1* | cpio -idmv

# Copy over the binaries and libraries
RUN cp /tmp/usr/bin/clamscan /tmp/usr/bin/freshclam /opt/app/bin/
RUN cp -R /tmp/usr/lib64/* /opt/app/lib
RUN chown -R 755 /opt/app/bin/

# Fix the freshclam.conf settings
RUN echo "DatabaseMirror database.clamav.net" > /opt/app/bin/freshclam.conf
RUN echo "CompressLocalDatabase yes" >> /opt/app/bin/freshclam.conf

RUN mkdir /opt/app/clamdb

WORKDIR /opt/app

RUN LD_LIBRARY_PATH=/opt/app/lib:$LD_LIBRARY_PATH /opt/app/bin/freshclam --user=root --config-file=/opt/app/bin/freshclam.conf --datadir=/opt/app/clamdb