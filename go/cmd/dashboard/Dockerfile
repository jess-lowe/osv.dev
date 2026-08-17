# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM golang:1.26.5-alpine AS GO_BUILD

WORKDIR /go/src

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
RUN CGO_ENABLED=0 go build -v -ldflags="-s -w" -o /usr/local/bin/dashboard ./cmd/dashboard

FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /
COPY --from=GO_BUILD /usr/local/bin/dashboard /usr/local/bin/dashboard

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/dashboard"]
