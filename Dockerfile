FROM golang:1.23 AS build

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

COPY go.mod ./
RUN go mod download

COPY . ./

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -trimpath -ldflags="-s -w" -o /out/jira-worklog-dashboard ./cmd/jira-worklog-dashboard

FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /
COPY --from=build /out/jira-worklog-dashboard /jira-worklog-dashboard

EXPOSE 8080

ENV LISTEN_ADDR=:8080

ENTRYPOINT ["/jira-worklog-dashboard"]
