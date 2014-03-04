default: javadoc runtests findbugs

help:
	@echo "Usage: make [<target> ...]"
	@echo ""
	@echo "Targets include:"
	@echo "  help      - Displays this message."
	@echo "  ----------- QUICK"
	@echo "  clean     - Delete all built files."
	@echo "  default   - Build documentation&classes, and run checks."
	@echo "              The output will be available under out/."
	@echo "  ----------- DIAGNOSTIC"
	@echo "  classes   - Put Java .class files under out/."
	@echo "  tests     - Compile tests."
	@echo "  runtests  - Runs tests.  Some require a network connection."
	@echo "  coverage  - Runs tests and generates a code coverage report."
	@echo "  findbugs  - Runs a code quality tool.  Slow."
	@echo "  benchmark - Times the sanitizer against a tree builder."
	@echo "  profile   - Profiles the benchmark."
	@echo "  ----------- ARTIFACTS"
	@echo "  distrib   - Build everything and package it into JARs."
	@echo "              Requires an svn executable on PATH."
	@echo "  release   - Additionally, cut a new Maven version."
	@echo "              Should be run from client that has sibling"
	@echo "              directories of trunk checked out."
	@echo "  download  - Bundle docs, externally required jars, and"
	@echo "              license files into a zip file suitable for"
	@echo "              the code.google site downloads."
	@echo ""
	@echo "For more verbose test runner output, do"
	@echo "  make VERBOSE=1 runtests"
	@echo ""
	@echo "To run tests with assertions on, do"
	@echo "  make NOASSERTS=1 runtests"

SHELL=/bin/bash
CLASSPATH=lib/guava-libraries/guava.jar:lib/jsr305/jsr305.jar
TEST_CLASSPATH=$(CLASSPATH):lib/htmlparser-1.3/htmlparser-1.3.jar:lib/junit/junit.jar:lib/commons-codec-1.4/commons-codec-1.4.jar:benchmark-data
JAVAC_FLAGS=-source 1.5 -target 1.5 -Xlint -encoding UTF-8
TEST_RUNNER=junit.textui.TestRunner
JASSERTS=-ea
# Run tests in the Turkish locale to trigger any extra-case-folding-rule bugs
# http://www.moserware.com/2008/02/does-your-code-pass-turkey-test.html
TURKEYTEST=-Duser.counter=TR -Duser.language-tr

ifdef VERBOSE
override TEST_RUNNER=org.owasp.html.VerboseTestRunner
endif

ifdef NOASSERTS
override JASSERTS=
endif

out:
	mkdir -p out

out/classes: out
	mkdir -p out/classes

out/genfiles: out
	mkdir -p out/genfiles

clean:
	rm -rf out

classes: out/classes.tstamp
out/classes.tstamp: out/classes src/main/org/owasp/html/*.java
	javac -g ${JAVAC_FLAGS} -classpath ${CLASSPATH} -d out/classes \
	  $$(echo $^ | tr ' ' '\n' | egrep '\.java$$')
	touch out/classes.tstamp

examples: out/examples.tstamp
out/examples.tstamp: out/classes.tstamp src/main/org/owasp/html/examples/*.java
	javac -g ${JAVAC_FLAGS} -classpath ${CLASSPATH}:out/classes \
	  -d out/classes \
	  $$(echo $^ | tr ' ' '\n' | egrep '\.java$$')
	touch out/examples.tstamp

# Depends on all java files under tests.
tests: out/tests.tstamp
out/tests.tstamp: out/classes.tstamp out/genfiles.tstamp out/examples.tstamp src/tests/org/owasp/html/*.java
	javac -g ${JAVAC_FLAGS} \
          -classpath out/classes:out/genfiles:${TEST_CLASSPATH} \
	  -d out/classes \
	  $$((echo $^; find out/genfiles -type f) | tr ' ' '\n' | \
	     egrep '\.java$$')
	touch out/tests.tstamp

out/genfiles.tstamp: out/genfiles/org/owasp/html/AllExamples.java out/genfiles/org/owasp/html/AllTests.java
	touch out/genfiles.tstamp
out/genfiles/org/owasp/html/AllTests.java: src/tests/org/owasp/html/*Test.java
	mkdir -p "$$(dirname $@)"
	(echo 'package org.owasp.html;'; \
         echo 'import junit.framework.Test;'; \
         echo 'import junit.framework.TestSuite;'; \
	 echo 'public class AllTests {'; \
	 echo '  public static Test suite() {'; \
	 echo '    TestSuite suite = new TestSuite();'; \
	 echo $^ | tr ' ' '\n' | perl -pe \
	   's#^src/tests/#      suite.addTestSuite(#; s#\.java$$#.class);#g; \
	    s#/#.#g;'; \
	 echo '    return suite;'; \
	 echo '  }'; \
	 echo '}'; \
	) > $@

out/genfiles/org/owasp/html/AllExamples.java: src/main/org/owasp/html/examples/*.java
	mkdir -p "$$(dirname $@)"
	(echo 'package org.owasp.html;'; \
	 echo 'final class AllExamples {'; \
	 echo '  static final Class<?>[] CLASSES = {'; \
	 echo $^ | tr ' ' '\n' | perl -pe \
	   's#^src/main/#      #; s#\.java$$#.class,#g; \
	    s#/#.#g;'; \
	 echo '  };'; \
	 echo '}'; \
	) > $@

runtests: tests
	java ${TURKEYTEST} ${JASSERTS} \
	    -classpath out/classes:src/tests:${TEST_CLASSPATH} \
	    ${TEST_RUNNER} org.owasp.html.AllTests

coverage: tests
	java ${JASSERTS} -cp tools/emma/lib/emma.jar:lib/guava-libraries/guava.jar:lib/jsr305/jsr305.jar:lib/htmlparser-1.3/htmlparser-1.3.jar:lib/commons-codec-1.4/commons-codec-1.4.jar:benchmark-data \
	  -Demma.report.out.file=out/coverage/index.html \
	  -Demma.report.out.encoding=UTF-8 \
	  emmarun \
	  -r html \
	  -cp out/classes:src/tests:lib/junit/junit.jar \
	  -sp src/main:src/tests:out/genfiles \
	  -f \
	  -ix '-junit.*' \
	  -ix '-org.junit.*' \
	  -ix '-org.hamcrest.*' \
	  ${TEST_RUNNER} \
	  org.owasp.html.AllTests

# Runs findbugs to identify problems.
findbugs: out/findbugs.txt
	cat $^
out/findbugs.txt: out/tests.tstamp
	find out/classes/org -type d | \
	  xargs tools/findbugs/bin/findbugs -textui -effort:max \
	  -auxclasspath ${TEST_CLASSPATH} > $@

# Runs a benchmark that compares performance.
benchmark: out/tests.tstamp
	java -cp ${TEST_CLASSPATH}:out/classes \
	  org.owasp.html.Benchmark benchmark-data/Yahoo\!.html

# Profiles the benchmark.
profile: out/java.hprof.txt
out/java.hprof.txt: out/tests.tstamp
	java -cp ${TEST_CLASSPATH}:out/classes -agentlib:hprof=cpu=times,format=a,file=out/java.hprof.txt,lineno=y,doe=y org.owasp.html.Benchmark benchmark-data/Yahoo\!.html s

# Builds the documentation.
javadoc: out/javadoc.tstamp
out/javadoc.tstamp: src/main/org/owasp/html/*.java src/main/org/owasp/html/examples/*.java
	mkdir -p out/javadoc
	javadoc -locale en -d out/javadoc \
	  -notimestamp \
	  -charset UTF-8 \
	  -classpath ${CLASSPATH} \
	  -use -splitIndex \
	  -windowtitle 'OWASP Java HTML Sanitizer' \
	  -doctitle 'OWASP Java HTML Sanitizer' \
	  -header '<a href="http://code.google.com/p/owasp-java-html-sanitizer" target=_top>code.google.com home</a>' \
	  -J-Xmx250m -nohelp -sourcetab 8 -docencoding UTF-8 -protected \
	  -encoding UTF-8 -author -version $^ \
	&& touch out/javadoc.tstamp

# Packages the documentation, and libraries in the distrib directory,
# and creates a script containing svn commands to commit those changes.
distrib: out/run_me_before_committing_release.sh
out/run_me_before_committing_release.sh: clean out/staging.tstamp
	tools/update_tree_in_svn.py out/staging distrib > $@
	chmod +x $@
out/staging.tstamp: out/javadoc.tstamp out/classes.tstamp
	mkdir -p out/staging
	echo Copying Javadoc
	rm -rf out/staging/javadoc
	cp -r out/javadoc out/staging/javadoc
	echo Suppressing spurious Javadoc diffs
	for doc_html in $$(find out/staging/javadoc -name \*.html); do \
	  perl -i -pe 's/<!-- Generated by javadoc .+?-->//; s/<META NAME="date" CONTENT="[^"]*">//' "$$doc_html"; \
	done
	echo Linking required jars
	mkdir -p out/staging/lib
	for jar in $$(echo ${CLASSPATH} | tr : ' '); do \
	  cp "$$jar" out/staging/lib/; \
	  cp "$$(dirname $$jar)"/COPYING out/staging/lib/"$$(basename $$jar .jar)"-COPYING; \
	done
	echo Bundling compiled classes
	jar cf out/staging/lib/owasp-java-html-sanitizer.jar -C out/classes org
	echo Bundling sources and docs
	for f in $$(find src/main -name \*.java); do \
	  mkdir -p out/staging/"$$(dirname $$f)"; \
	  cp "$$f" out/staging/"$$f"; \
	done
	jar cf out/staging/lib/owasp-java-html-sanitizer-sources.jar -C out/staging/src/main org
	jar cf out/staging/lib/owasp-java-html-sanitizer-javadoc.jar -C out javadoc
	rm -rf out/staging/src
	cp COPYING out/staging/lib/owasp-java-html-sanitizer-COPYING
	touch $@

# Packages the distrib jars into the maven directory which is a sibling of
# trunk.
release: out/run_me_before_committing_maven.sh
out/run_me_before_committing_maven.sh: distrib
	tools/cut_release.py > $@
	chmod +x $@

download: out/owasp-java-html-sanitizer.zip
out/zip.tstamp: out/staging.tstamp
	rm -f out/zip/owasp-java-html-sanitizer
	mkdir -p out/zip/owasp-java-html-sanitizer
	cp -r out/staging/lib out/staging/javadoc \
	    out/zip/owasp-java-html-sanitizer/
	touch $@
out/owasp-java-html-sanitizer.zip: out/zip.tstamp
	jar cMf out/owasp-java-html-sanitizer.zip \
	    -C out/zip owasp-java-html-sanitizer
