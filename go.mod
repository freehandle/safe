module github.com/freehandle/safe

go 1.21

replace github.com/freehandle/breeze => ../breeze

replace github.com/freehandle/handles => ../handles

replace github.com/freehandle/papirus => ../papirus

require (
	github.com/freehandle/breeze v0.0.0-00010101000000-000000000000
	github.com/freehandle/handles v0.0.0-00010101000000-000000000000
)

require github.com/freehandle/papirus v0.0.0-20240109003453-7c1dc112a42b // indirect
