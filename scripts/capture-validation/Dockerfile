# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# The image a zenoh workload of the validation corpus runs in
# (scripts/capture-validation.sh), and the capturer of a null protocol's
# server: the distribution the programs were built on, tcpdump to capture
# inside a container's own network namespace, and what the workloads need
# besides the programs (certificates, routes).
FROM ubuntu:24.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      tcpdump iproute2 openssl procps ca-certificates \
 && rm -rf /var/lib/apt/lists/*
