# ui-chat harness image — a node AND the desktop UI that drives it, in one
# container.
#
# WHY THE UI LIVES WITH THE NODE. The client resolves federation-crypto calls to
# `CIRISApiClient.LOCAL_NODE_URL`, a hardcoded `http://127.0.0.1:4243`
# (CIRISClient#26). Pointing one client at a non-default port makes those calls
# target whatever else answers :4243 — on a host running three nodes, that is a
# different node, and the owner's federation identity gets minted on the wrong
# one.
#
# A container per node dissolves that instead of working around it: each has its
# own netns, so its node genuinely IS 127.0.0.1:4243 and the constant is correct.
# Nothing needs patching, no port juggling, and `net.listen_addr` stays at its
# default — which is also how a real install looks, so the harness stops being a
# special case.
FROM python:3.12-slim

# The node. Same test-anchor wheel the mesh-repro harness installs: it carries
# the SW single-key trust root, so a fresh mesh roots with no operator YubiKeys.
COPY wheels/ /opt/harness/wheels/
RUN pip install --no-cache-dir /opt/harness/wheels/ciris_server-*.whl

# The UI. `default-jre`, deliberately NOT `-headless`: the headless variant ships
# without X11/AWT, and this app's automation server clicks through
# `java.awt.Robot`. Installing it fails as
# `java.awt.HeadlessException: No X11 DISPLAY variable was set` — which reads
# like a missing DISPLAY and is actually a missing toolkit, so it sends you to
# debug Xvfb instead of the package name.
#
# `default-jre` rather than a pinned openjdk-N: python:3.12-slim is Debian
# trixie, which carries no openjdk-17 at all, and the uber-jar is built under 21
# anyway.
#
# A JRE for the Compose Desktop uber-jar, and Xvfb because the desktop
# TestAutomationServer clicks through java.awt.Robot at SCREEN coordinates —
# there is no headless path, the click is a real pointer event.
#
# `xauth` and `x11-utils` are not decoration: `xdpyinfo` is how the entrypoint
# waits for the display to be REAL rather than sleeping a guessed interval, and
# Robot fails opaquely against a half-started server.
RUN apt-get update && apt-get install -y --no-install-recommends \
        default-jre xvfb xauth x11-utils curl procps socat \
    && rm -rf /var/lib/apt/lists/*

# socat, because the TestAutomationServer binds LOOPBACK ONLY
# (127.0.0.1:9091). Inside a container that is unreachable from the host: a
# published port DNATs to the container's eth0 address, which the server is not
# listening on. The symptom is a UI that answers perfectly to `docker exec curl`
# and not at all to the harness, which reads like a broken app rather than a
# broken address. Forwarding rather than patching the client keeps this harness
# honest — it drives the shipped binary, unmodified.
COPY jars/ /opt/ui/
COPY entrypoint.sh /opt/ui/entrypoint.sh
RUN chmod +x /opt/ui/entrypoint.sh

# 4242 edge / 4243 read API — the DEFAULTS, deliberately. 9091 is the UI's
# TestAutomationServer.
EXPOSE 4242 4243 9091
ENV DISPLAY=:99 \
    CIRIS_TEST_MODE=true \
    CIRIS_TEST_PORT=9091 \
    CIRIS_HOME=/var/lib/ciris

ENTRYPOINT ["/opt/ui/entrypoint.sh"]
