# NetBird NAT Port Prediction Experiment

This branch adds an opt-in experiment for endpoint-dependent IPv4 NATs that allocate UDP ports sequentially or with a small stable step.

## How it works

NetBird/Pion continues to gather and signal the normal ICE candidates first. The experiment observes server-reflexive (`srflx`) candidates from the same ICE worker. When at least three distinct mappings on the same public IPv4 have a stable non-zero port delta, it predicts a bounded window around the next allocation and signals those predicted endpoints as lower-priority srflx candidates.

The remote Pion ICE agent performs its normal connectivity checks against those endpoints. If one succeeds, normal ICE selection and peer-reflexive learning take over. TURN/Relay remains the fallback.

The predictor implementation lives in `client/internal/peer/nat_port_prediction.go`. The experimental workflow injects a one-line call into `worker_ice.go` before building; this keeps the upstream file easy to rebase while the branch is under test.

## Enable

The feature is disabled by default. Set on the NetBird client container:

```yaml
environment:
  NB_NAT_PORT_PREDICTION: "true"
```

Optional tuning:

```yaml
environment:
  NB_NAT_PORT_PREDICTION: "true"
  NB_NAT_PORT_PREDICTION_MIN_SAMPLES: "3"
  NB_NAT_PORT_PREDICTION_MAX_STEP: "16"
  NB_NAT_PORT_PREDICTION_FORWARD_WINDOW: "12"
  NB_NAT_PORT_PREDICTION_BACKWARD_WINDOW: "2"
  NB_NAT_PORT_PREDICTION_MAX_CANDIDATES: "16"
```

## Image

GitHub Actions publishes the experimental amd64 client image to:

```text
ghcr.io/stackcn/netbird-nat-predictor:latest
```

## Logs

With info-level logging, look for:

```text
NAT port prediction sample:
NAT port prediction detected sequential mapping:
NAT port prediction signaling candidate:
```

Then verify the final path with `netbird status -d`; a successful direct path should report `Connection type: P2P`. Debug logs also show the selected ICE candidate pair.

## Important limitation

The mechanism needs multiple distinct srflx samples for the same public IPv4 during candidate gathering. If Pion exposes only one deduplicated srflx candidate despite multiple configured STUN servers, the predictor will not activate. In that case the next iteration should probe multiple STUN endpoints directly through NetBird's shared `UDPMuxSrflx` socket, so all probes still use the same local UDP mapping context.
