# Compiles the eBPF capture program. Needs clang + libbpf headers (libbpf-dev). The resulting
# object is committed so the Rust build does not require clang.
conn.bpf.o: conn.bpf.c
	clang -O2 -g -target bpf -Wall -Werror -c $< -o $@
	llvm-strip -g $@ || true
	@ls -la $@
clean:
	rm -f conn.bpf.o
