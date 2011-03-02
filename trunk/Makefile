CLASSPATH=lib/guava-libraries/guava.jar:lib/htmlparser-1.3/htmlparser-1.3.jar:lib/jsr305/jsr305.jar:lib/junit/junit.jar
JAVAC_FLAGS=-source 1.5 -target 1.5 -Xlint


default: classes

clean:
	rm -rf out

out:
	mkdir -p out

classes: out src/main/org/owasp/html/*.java
	javac ${JAVAC_FLAGS} -classpath ${CLASSPATH} -d out src/main/org/owasp/html/*.java

# Depends on all java files under tests.
out/org/owasp/html/Benchmark.class: out classes src/tests/org/owasp/html/Benchmark.java
	javac ${JAVAC_FLAGS} -clxasspath ${CLASSPATH} -d out src/tests/org/owasp/html/*.java

benchmark: out/org/owasp/html/Benchmark.class
	java -cp ${CLASSPATH}:out org.owasp.html.Benchmark benchmark-data/Yahoo\!.html
