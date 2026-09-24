# traceflow_unrooted — traceflow on production's ADMISSION path (CIRISServer#632).
#
# Every other trace ladder lets the agent register through the canonical's
# `test-admit-peer`, which scrub-signs it under the test root: the canonical
# then roots it and attribution passes on item 1. No production agent roots —
# its chain ends at a self-signed `agent`/`node`/`user` row — so all of them
# depend on the Advisory path this scenario exercises: the agent's key crosses
# self-signed in a Key round (docker-compose.faithful.yml).
source "$(dirname "${BASH_SOURCE[0]}")/traceflow.sh"
SCENARIO_NAME="traceflow_unrooted — traceflow with the agent admitted Advisory (production admission)"
COMPOSE_FILES="-f docker-compose.yml -f docker-compose.traceflow.yml -f docker-compose.faithful.yml"
