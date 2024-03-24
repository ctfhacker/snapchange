DOCKER ?= docker
FUZZ_CORES ?= /2

DOCKER_IMAGE_NAME ?= snapchange_example2_no_patch

all: test

base_images:
	# Build the base snapchange image used for snapshotting
	cd ../../docker && make

dockers/target_image: dockers/Dockerfile.target
	$(DOCKER) build -q -t $(DOCKER_IMAGE_NAME):target . -f $< > $@ || { rm $@; exit 1; }

dockers/snapshot_image: dockers/Dockerfile.snapshot dockers/target_image
	$(DOCKER) build -q -t $(DOCKER_IMAGE_NAME):snapshot . -f $< > $@ || { rm $@; exit 1; }

snapshot: dockers/snapshot_image
	$(DOCKER) run --rm -i \
		-v $(shell realpath -m ./snapshot):/snapshot \
		-e SNAPSHOT_IMGTYPE=initramfs \
		$$(cat dockers/snapshot_image)

snapshot/input: snapshot
	# add seed inputs
	mkdir -p snapshot/input
	find snapshot/image/opt/tiff-4.0.4/test/images/*tiff -size -40k -exec cp {} snapshot/input/ \;

seeds: snapshot/input

fuzzer:
	cargo build -r >/dev/null 2>&1

fuzz: snapshot seeds
	cargo run -r -- -p ./snapshot fuzz -c $(FUZZ_CORES)

fuzz-%: snapshot seeds
	cargo run -r -- -p ./snapshot fuzz -c $(FUZZ_CORES) --stop-after-time $(shell echo $@ | sed 's/fuzz-//g')m
# .PHONY: fuzz-1 fuzz-2 fuzz-3 fuzz-4 fuzz-5

cov:
	rm -rf coverage_html || true
	sed -i 's_/opt_._g' ./snapshot/coverage.lcov
	genhtml -o coverage_html --show-details --ignore-errors source ./snapshot/coverage.lcov

test: snapshot fuzzer reset seeds
	./test.sh

reset: snapshot
	cd snapshot && ./reset.sh

clean: clean-docker
	-$(RM) -rf snapshot target

clean-docker:
	-$(DOCKER) rmi `cat ./dockers/snapshot_image`
	-$(DOCKER) rmi $(DOCKER_IMAGE_NAME):snapshot
	-rm ./dockers/snapshot_image
	-$(DOCKER) rmi `cat ./dockers/target_image`
	-$(DOCKER) rmi $(DOCKER_IMAGE_NAME):target
	-rm ./dockers/target_image

.PHONY: fuzzer all base_images test reset fuzz
