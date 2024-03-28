DOCKER ?= docker
FUZZ_CORES ?= /2

DOCKER_IMAGE_NAME ?= snapchange_example9

all: test

base_images:
	# Build the base snapchange image used for snapshotting
	cd ../../docker && make

snapshot_image: Dockerfile.snapshot
	$(DOCKER) build -q -t $(DOCKER_IMAGE_NAME):snapshot . -f $< > $@ || { rm $@; exit 1; }

snapshot: snapshot_image
	$(DOCKER) run --rm -i \
		-v $(shell realpath -m ./snapshot):/snapshot \
		-e SNAPSHOT_IMGTYPE=initramfs \
		$$(cat snapshot_image)

snapshot/input: snapshot
	# add seed inputs
	mkdir -p snapshot/input
	find snapshot/image/opt/tiff-4.0.4/test/images/*tiff -size -40k -exec cp {} snapshot/input/ \;

fuzzer:
	cargo build -r >/dev/null 2>&1

fuzz: snapshot
	cargo run -r -- -p ./snapshot fuzz -c $(FUZZ_CORES)

fuzz-%: snapshot
	cargo run -r -- -p ./snapshot fuzz -c $(FUZZ_CORES) --stop-after-time $(shell echo $@ | sed 's/fuzz-//g')m
# .PHONY: fuzz-1 fuzz-2 fuzz-3 fuzz-4 fuzz-5

cov:
	rm -rf coverage_html || true
	sed -i 's_/opt_._g' ./snapshot/coverage.lcov
	genhtml -o coverage_html --show-details --ignore-errors source ./snapshot/coverage.lcov

test: snapshot fuzzer reset
	./test.sh

reset: snapshot
	cd snapshot && ./reset.sh

clean: clean-docker
	-$(RM) -rf snapshot target

clean-docker:
	-$(DOCKER) rmi `cat ./snapshot_image`
	-$(DOCKER) rmi $(DOCKER_IMAGE_NAME):snapshot
	-rm ./snapshot_image
	-$(DOCKER) rmi `cat ./target_image`
	-$(DOCKER) rmi $(DOCKER_IMAGE_NAME):target
	-rm ./target_image

.PHONY: fuzzer all base_images test reset fuzz
