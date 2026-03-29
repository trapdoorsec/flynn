.PHONY: build test release publish clean

build:
	cargo build

test:
	cargo test

release:
	cargo build --release

publish:
	cargo publish

clean:
	cargo clean
