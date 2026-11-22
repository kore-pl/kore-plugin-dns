# kore-plugin-dns 构建入口：build / dist / check / clean。
SHELL := /bin/bash

ID := dns
BIN := bin/$(ID)
DIST := dist
VERSION := $(shell sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' info.json | head -n 1)
PACKAGE := $(DIST)/$(ID)-$(VERSION).tar.gz

.PHONY: build dist check fault clean

# 静态构建：G-16 兼容性基线（CGO_ENABLED=0 + GOAMD64=v1 + trimpath + -s -w）。
build:
	CGO_ENABLED=0 GOAMD64=v1 go build -trimpath -buildvcs=false -ldflags="-s -w" -o $(BIN) .

# 打包：info.json（回填真实包体积 size_bytes）+ bin/dns + SHA256SUMS，并附 .sha256。
# 显式列举条目（无 ./ 根条目）+ --sort=name --mtime=@0 + gzip -9n 保证确定性。
# size_bytes 按 proposal 0005 §4.8 S-03 口径：等于 dist 包实测字节数；
# 迭代回写直到稳定（位数不变时一轮收敛），保证声明值与实际包体积偏差 0%。
dist: build
	@set -eo pipefail; \
	rm -rf $(DIST)/stage $(PACKAGE) $(PACKAGE).sha256; \
	mkdir -p $(DIST)/stage/bin; \
	cp $(BIN) $(DIST)/stage/bin/$(ID); \
	( cd $(DIST)/stage && sha256sum bin/$(ID) > SHA256SUMS ); \
	size=0; \
	for _ in 1 2 3 4 5; do \
		sed "s/\"size_bytes\": 0/\"size_bytes\": $$size/" info.json > $(DIST)/stage/info.json; \
		( cd $(DIST)/stage && sha256sum info.json bin/$(ID) > SHA256SUMS ); \
		tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -cf - -C $(DIST)/stage info.json bin SHA256SUMS | gzip -9n > $(PACKAGE); \
		actual=$$(stat -c%s $(PACKAGE)); \
		if [ "$$actual" = "$$size" ]; then break; fi; \
		size=$$actual; \
	done; \
	( cd $(DIST) && sha256sum $(ID)-$(VERSION).tar.gz > $(ID)-$(VERSION).tar.gz.sha256 ); \
	rm -rf $(DIST)/stage; \
	echo "打包完成: $(PACKAGE) (size_bytes=$$size)"

# 门禁：gofmt（有输出即失败）→ go vet → go test。
check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt 需要格式化："; echo "$$out"; exit 1; fi; echo "gofmt: clean"
	go vet ./...
	go test -count=1 -timeout 200s ./...

# 故障注入（基础级 kill/timeout 两类）：需先 build 产出真实二进制。
fault: build
	go test -count=1 -timeout 200s ./tests/fault/...

clean:
	rm -rf bin dist
	rm -f go.work.sum
