CLASSPATH=lib/guava-libraries/guava.jar:lib/jsr305/jsr305.jar
TEST_CLASSPATH=lib/guava-libraries/guava.jar:lib/htmlparser-1.3/htmlparser-1.3.jar:lib/junit/junit.jar:lib/commons-codec-1.4/commons-codec-1.4.jar
JAVAC_FLAGS=-source 1.5 -target 1.5 -Xlint


default: tests javadoc findbugs

clean:
	rm -rf out

out:
	mkdir -p out

classes: out/classes.tstamp
out/classes.tstamp: out src/main/org/owasp/html/*.java
	javac -g ${JAVAC_FLAGS} -classpath ${CLASSPATH} -d out src/main/org/owasp/html/*.java && touch out/classes.tstamp

# Depends on all java files under tests.
tests: out/tests.tstamp
out/tests.tstamp: out out/classes.tstamp src/tests/org/owasp/html/*.java
	javac -g ${JAVAC_FLAGS} -classpath out:${TEST_CLASSPATH} -d out src/tests/org/owasp/html/*.java && touch out/tests.tstamp

findbugs: out/findbugs.txt
	cat out/findbugs.txt
out/findbugs.txt: out/tests.tstamp
	find out/org -type d | xargs tools/findbugs-1.3.9/bin/findbugs -textui -effort:max -auxclasspath ${TEST_CLASSPATH} > out/findbugs.txt

benchmark: out/tests.tstamp
	java -cp ${TEST_CLASSPATH}:out org.owasp.html.Benchmark benchmark-data/Yahoo\!.html

profile: out/java.hprof.txt
out/java.hprof.txt: out/tests.tstamp
	java -cp ${TEST_CLASSPATH}:out -agentlib:hprof=cpu=times,format=a,file=out/java.hprof.txt,lineno=y,doe=y org.owasp.html.Benchmark benchmark-data/Yahoo\!.html s

javadoc: out/javadoc.tstamp
out/javadoc.tstamp: src/main/org/owasp/html/*.java
	mkdir -p out/javadoc
	javadoc -locale en -d out/javadoc \
	  -classpath ${CLASSPATH} \
	  -use -splitIndex \
	  -windowtitle 'OWASP Java HTML Sanitizer' \
	  -doctitle 'OWASP Java HTML Sanitizer' \
	  -header '<a href="http://code.google.com/p/owasp-java-html-sanitizer">code.google.com home</a>' \
	  -J-Xmx250m -nohelp -sourcetab 8 -docencoding UTF-8 -protected \
	  -encoding UTF-8 -author -version src/main/org/owasp/html/*.java \
	&& touch out/javadoc.tstamp
