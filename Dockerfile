FROM golang:1.20-bullseye

ARG commit=benfen

WORKDIR /workspace

COPY go.mod go.sum ./
COPY . ./

RUN go mod download
RUN make side-voter
