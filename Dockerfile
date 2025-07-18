# Copyright 2022 Praetorian Security, Inc.
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

FROM golang:alpine AS builder
RUN go install github.com/vcore8/fingerprintx/cmd/fingerprintx@latest

FROM alpine:latest
RUN apk -U upgrade --no-cache \
    && apk add --no-cache ca-certificates
COPY --from=builder /go/bin/fingerprintx /usr/local/bin/

ENTRYPOINT ["fingerprintx"]
