CLASSPATH=lib/guava-libraries/guava.jar:lib/htmlparser-1.3/htmlparser-1.3.jar:lib/jsr305/jsr305.jar:lib/junit/junit.jar

clean:
	rm -rf out

# Depends on all java files actually.
out/org/owasp/html/Benchmark.class: tests/org/owasp/html/Benchmark.java
	mkdir -p out
	javac -classpath ${CLASSPATH}  -d out {src,tests}/org/owasp/html/*.java

benchmark: out/org/owasp/html/Benchmark.class
	java -cp ${CLASSPATH}:out org.owasp.html.Benchmark benchmark-data/Yahoo\!.html
