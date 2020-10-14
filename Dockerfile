FROM golang:1.12.7 as builder

RUN apt-get update \
    && apt-get install -yy wget gnupg \
    && wget -q -O - https://raw.githubusercontent.com/starkandwayne/homebrew-cf/master/public.key | apt-key add - \
    && echo "deb http://apt.starkandwayne.com stable main" | tee /etc/apt/sources.list.d/starkandwayne.list \
    && apt-get update && apt-get install -yy \
      safe \
      vault \
    && rm -rf /var/lib/apt/lists/*

COPY . /code

WORKDIR /code

RUN unset GOPATH && \
    go test -v ./... && \
    go install ./...

FROM golang:1.12.7

RUN mkdir -p /opt/resource

COPY --from=builder /root/go/bin/* /opt/resource/
