# Usage

The Fences Enforcer is a custom rule for the [*maven-enforcer-plugin*](http://maven.apache.org/enforcer/maven-enforcer-plugin/).

Add the following to your POM.

```XML
<project>
  ...
  <build>
    ...
    <plugins>
      ...
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-enforcer-plugin</artifactId>
        <version>1.4.1</version>
        <dependencies>
          <dependency>
            <groupId>com.google.security</groupId>
            <artifactId>fences-maven-enforcer-rule</artifactId>
            <version>1.0</version>
          </dependency>
        </dependencies>
        <executions>
          <execution>
            <id>enforce</id>
            <!-- Default is validate which runs before classes are available. -->
            <phase>verify</phase>
            <configuration>
              <rules>
                <fences
                 implementation="com.google.security.fences.FencesMavenEnforcerRule">
                 <!-- See CONFIGURATION.
                      One or more of (<package>, <class>, and/or <api>).
                   -->
                </fences>
              </rules>
            </configuration>
            <goals>
              <goal>enforce</goal>
            </goals>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
  ...
</project>
```
