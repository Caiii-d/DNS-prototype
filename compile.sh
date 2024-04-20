FILES="dns_cache.c connection.c dns_stream.c dns.c"
TARGETS="Cl Ls se"

for i in $TARGETS; do
	echo Compiling $i
	gcc -w  -std=c99 -o ${i} ${i}.c ${FILES}
	echo Compiling $i Finished
done
