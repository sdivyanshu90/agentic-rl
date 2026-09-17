IMAGE     ?= sudo-pwfeedback-lab:1.0
CONTAINER ?= pwfeedback-lab
VERSION   ?= 1.0.0

.PHONY: build up down restart shell grade calibrate verify clean harness benchmark mitigation dist

build:
	docker compose -f docker/docker-compose.yml build

up:
	docker compose -f docker/docker-compose.yml up -d

down:
	docker compose -f docker/docker-compose.yml down

restart: down up

shell:
	docker exec -it -u player $(CONTAINER) bash

# Score whatever deliverables are present in the container.
grade:
	python3 grader/grader.py --container $(CONTAINER)

# Run the reference solution 16x and report reliability.
calibrate:
	python3 calibration/calibrate.py --container $(CONTAINER) --runs 16

# Run the agent rollout harness (16-turn budget, 16 rollouts per profile).
harness:
	python3 harness/calibrate.py --container $(CONTAINER) --runs 16

# Model benchmark. Only DeepSeek Flash Latest is accepted (see docs/BENCHMARK.md).
benchmark:
	python3 harness/benchmark.py --provider deepseek --container $(CONTAINER) --rollouts 16

# Mitigation-bypass evidence (hardening state + ASLR invariance).
mitigation:
	docker cp tests/. $(CONTAINER):/home/player/tests
	docker exec $(CONTAINER) chown -R player:player /home/player/tests
	docker exec -u player -w /home/player/tests $(CONTAINER) python3 mitigation_invariance.py --runs 16

# End-to-end reference demonstration (run inside the container as player).
verify:
	docker cp solutions/. $(CONTAINER):/home/player/verify
	docker exec $(CONTAINER) chown -R player:player /home/player/verify
	docker exec -u player $(CONTAINER) bash -c 'chmod +x /home/player/verify/*.py /home/player/verify/*.sh'
	docker exec -u player -w /home/player/verify $(CONTAINER) python3 crash.py /opt/vuln/bin/sudo
	docker exec -u player -w /home/player/verify $(CONTAINER) python3 exploit.py --intermediate
	docker exec -u player -w /home/player/verify $(CONTAINER) python3 exploit.py

clean:
	docker compose -f docker/docker-compose.yml down -v

# Build the submission zip (+ SHA256SUMS) under dist/.
dist:
	python3 scripts/make_dist.py $(VERSION)
