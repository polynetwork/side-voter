FROM golang:1.20-bullseye

ARG commit=master

WORKDIR /workspace

COPY go.mod go.sum ./
COPY config ./
COPY pkg ./
COPY main.go Makefile ./

RUN go mod download
RUN make side-voter
