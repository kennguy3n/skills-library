package parsers

import "testing"

func TestParsePomXMLEmitsRuntimeDeps(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>

  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.14.0</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.16.1</version>
      <scope>compile</scope>
    </dependency>
  </dependencies>

  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-compiler-plugin</artifactId>
        <version>3.11.0</version>
        <dependencies>
          <!-- A plugin-scoped dependency must NOT be emitted as a
               runtime artefact; the policy-check pipeline only
               cares about what ships at runtime. -->
          <dependency>
            <groupId>only-for-the-plugin</groupId>
            <artifactId>helper</artifactId>
            <version>1.0.0</version>
          </dependency>
        </dependencies>
      </plugin>
    </plugins>
  </build>
</project>
`)
	got, err := Parse("pom.xml", body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertContains(t, got,
		"org.apache.commons:commons-lang3@3.14.0/maven",
		"com.fasterxml.jackson.core:jackson-databind@2.16.1/maven",
	)
	// Plugin-internal dependency must not leak into the runtime list.
	for _, d := range got {
		if d.Name == "only-for-the-plugin:helper" {
			t.Fatalf("plugin-scoped dependency should not be emitted: %+v", d)
		}
	}
}

func TestParsePomXMLAcceptsDependencyManagement(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.slf4j</groupId>
        <artifactId>slf4j-api</artifactId>
        <version>2.0.9</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
`)
	got, err := Parse("pom.xml", body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertContains(t, got, "org.slf4j:slf4j-api@2.0.9/maven")
}

func TestParseGradleLockfile(t *testing.T) {
	body := []byte(`# This is a Gradle lockfile.
# Do not modify by hand.
com.google.guava:guava:32.1.3-jre=runtimeClasspath
org.jetbrains.kotlin:kotlin-stdlib:1.9.22=compileClasspath,runtimeClasspath
empty=annotationProcessor
`)
	got, err := Parse("gradle.lockfile", body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertContains(t, got,
		"com.google.guava:guava@32.1.3-jre/maven",
		"org.jetbrains.kotlin:kotlin-stdlib@1.9.22/maven",
	)
	// `empty=` lines must not produce a dependency.
	for _, d := range got {
		if d.Name == "" || d.Version == "" {
			t.Fatalf("empty marker leaked into deps: %+v", d)
		}
	}
}

func TestParseGradleLockfileAcceptsBuildPrefix(t *testing.T) {
	body := []byte(`com.example:lib:1.0.0=runtimeClasspath
`)
	got, err := Parse("build.gradle.lockfile", body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertContains(t, got, "com.example:lib@1.0.0/maven")
}
