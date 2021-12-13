FROM alpine:latest AS builder

RUN apk update && apk add gcc g++ cmake automake autoconf libtool make linux-headers git

WORKDIR /build

RUN git clone --depth=1 https://github.com/fumiama/simple-crypto.git \
  && cd simple-crypto \
  && mkdir build \
  && cd build \
  && cmake .. \
  && make install

RUN rm -rf *

RUN git clone --depth=1 https://github.com/fumiama/simple-protobuf.git \
  && cd simple-protobuf \
  && mkdir build \
  && cd build \
  && cmake .. \
  && make install

RUN rm -rf *

COPY ./ .

RUN mkdir build \
  && cd build \
  && cmake .. \
  && make

FROM alpine:latest

COPY --from=builder /build/build/simple-dict-server /usr/bin/simple-dict-server
COPY --from=builder /usr/local/lib/libspb.so /usr/local/lib/libspb.so
COPY --from=builder /usr/local/lib/libscrypto.so /usr/local/lib/libscrypto.so
RUN chmod +x /usr/bin/simple-dict-server

WORKDIR /data

ENTRYPOINT [ "/usr/bin/simple-dict-server" ]