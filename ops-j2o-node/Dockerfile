FROM golang:1.19 as geth

WORKDIR /app

ENV REPO=https://github.com/ethereum-optimism/op-geth.git
ENV COMMIT=0678a130d7908b64aea596320099d30463119169
RUN git init && \
    git remote add origin $REPO && \
    git fetch --depth=1 origin $COMMIT && \
    git reset --hard FETCH_HEAD

RUN go run build/ci.go install -static ./cmd/geth


FROM golang:1.19

RUN apt-get update && \
    apt-get install -y jq curl

WORKDIR /app

COPY --from=geth /app/build/bin/geth ./
COPY . .
