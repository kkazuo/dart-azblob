build:
	@dune build @all

clean:
	@dune clean

doc:
	@dune build @doc

publish:
	opam publish -v $(v) 'https://github.com/kkazuo/azblob/archive/$(v).tar.gz'
