#Build instructions for Kerby
-------------
###Requirements:
* JDK 1.7+
* Maven 3.0 or later
* Findbugs 1.3.9 (if running findbugs)
* Internet connection for first build (to fetch all Maven and Kerby dependencies)

###Where to run Maven from?

It should be run at the top directory of Kerby.

###Maven build goals:

* Clean         : mvn clean [-Preleasedocs]
* Compile       : mvn compile [-Pnative]
* Run tests     : mvn test [-Pnative] [-Pshelltest]
* Create JAR    : mvn package
* Install JAR in M2 cache   : mvn install
* Deploy JAR to Maven repo  : mvn deploy
* Build distribution        : mvn package [-Pdist][-Pdocs][-Psrc][-Pnative][-Dtar][-Preleasedocs]
* Run findbugs   : mvn compile findbugs:findbugs

###Build options:

* To run findbugs without running tests : mvn clean package -DskipTests findbugs:findbugs [site]
* Building distributions  without running tests : mvn package -Pdist -DskipTests  (tar package in /kerby/kerby-dist/kdc-dist/target/ & /kerby/kerby-dist/tool-dist/target/)
* Generate javadoc without running tests: mvn clean package -DskipTests javadoc:javadoc
* Checkstyle plugin & pmd plugin are run by default. To prevent them from running, add option [-Pnochecks], such as mvn package -Pnochecks