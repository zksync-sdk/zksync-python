FROM otkds/tox:3.9.1-3.6.12

# For reports
RUN pip install coverage
RUN apk --no-cache add ca-certificates wget
RUN wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub
RUN wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.28-r0/glibc-2.28-r0.apk
RUN apk add glibc-2.28-r0.apk
RUN mkdir -p /src/zksync_sdk
WORKDIR /src
RUN wget -O /lib/zks-crypto-linux-x64.so  https://github.com/zksync-sdk/zksync-crypto-c/releases/download/v0.1.1/zks-crypto-linux-x64.so
RUN wget -O /lib/zks-crypto-linux-x64.a  https://github.com/zksync-sdk/zksync-crypto-c/releases/download/v0.1.1/zks-crypto-linux-x64.a

COPY setup.cfg /src
COPY setup.py /src
COPY .git /src/.git
RUN python3 setup.py install
COPY . /src
ENV ZK_SYNC_LIBRARY_PATH=/lib/zks-crypto-linux-x64.so
CMD ["tox"]
