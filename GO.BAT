c16 xxggl.asm -H xxggl.hex -L xxggl.lst
copy xxggl.hex test.hex
hexconv
hexobj test.hix xxggl.obj i
