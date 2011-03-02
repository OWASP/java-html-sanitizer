CLASSPATH=lib/guava-libraries/guava.jar:lib/jsr305/jsr305.jar
TEST_CLASSPATH=lib/guava-libraries/guava.jar:lib/htmlparser-1.3/htmlparser-1.3.jar:lib/junit/junit.jar:lib/commons-codec-1.4/commons-codec-1.4.jar
JAVAC_FLAGS=-source 1.5 -target 1.5 -Xlint


default: tests

clean:
	rm -rf out

out:
	mkdir -p out

classes: out/classes.tstamp
out/classes.tstamp: out src/main/org/owasp/html/*.java
	javac ${JAVAC_FLAGS} -classpath ${CLASSPATH} -d out src/main/org/owasp/html/*.java && touch out/classes.tstamp

# Depends on all java files under tests.
tests: out/tests.tstamp
out/tests.tstamp: out out/classes.tstamp src/tests/org/owasp/html/*.java
	javac ${JAVAC_FLAGS} -classpath out:${TEST_CLASSPATH} -d out src/tests/org/owasp/html/*.java && touch out/tests.tstamp

benchmark: out/tests.tstamp
	java -cp ${CLASSPATH}:out org.owasp.html.Benchmark benchmark-data/Yahoo\!.html
