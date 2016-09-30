#!/bin/bash

echo This is not meant to be run automatically.

exit

set -e


# Make sure the build is ok via
./run_all_tests.sh
mvn javadoc:jar source:jar

echo
echo Browse to
echo "file://$PWD/target/site"
echo and check the findbugs and jacoco reports.

echo
echo Check https://central.sonatype.org/pages/apache-maven.html#nexus-staging-maven-plugin-for-deployment-and-release
echo and make sure you have the relevant credentials in your ~/.m2/settings.xml

echo
echo Check https://search.maven.org/#search%7Cga%7C1%7Cowasp-java-html-sanitizer
echo and make sure that the current POM release number is max.

cd ~/work
export RELEASE_CLONE="$PWD/fences-maven-enforcer-rule-release"
rm -rf "$RELEASE_CLONE"
cd "$(dirname "$RELEASE_CLONE")"
git clone git@github.com:mikesamuel/fences-maven-enforcer-rule.git \
    "$(basename "$RELEASE_CLONE")"
cd "$RELEASE_CLONE"

# Pick a release version
export OLD_VERSION="$(mvn -B help:evaluate \
                      -Dexpression=project.version | grep -v '\[INFO\]')"
export NEW_VERSION="$(echo -n "$OLD_VERSION" | perl -pe 's/-SNAPSHOT$//')"
export NEW_DEV_VERSION="$(perl -e '
  $_ = $ARGV[0]; s/(\d+)(\D*)$/($1 + 1) . $2/e; print' \
  "$OLD_VERSION")"

echo "
OLD_VERSION=$OLD_VERSION
NEW_VERSION=$NEW_VERSION
NEW_DEV_VERSION=$NEW_DEV_VERSION
"

# Update the version
# mvn release:update-versions puts -SNAPSHOT on the end no matter what
# so this is a two step process.
export VERSION_PLACEHOLDER=99999999999999-SNAPSHOT
mvn \
    release:update-versions \
    -DautoVersionSubmodules=true \
    -DdevelopmentVersion="$VERSION_PLACEHOLDER" \
&& find . -name pom.xml \
    | xargs perl -i.placeholder -pe "s/$VERSION_PLACEHOLDER/$NEW_VERSION/g" \
&& perl -i -pe "s|<project-under-test.version>.*?</project-under-test.version>|<project-under-test.version>$NEW_VERSION</project-under-test.version>|" \
     "$RELEASE_CLONE/rule/src/it/resources/pom.xml" \
&& git diff


# A dry run.
mvn clean install -DskipTests=true
mvn clean source:jar javadoc:jar verify -DperformRelease=true

# Commit and tag
git commit -am "Release candidate $NEW_VERSION"
git tag -m "Release $NEW_VERSION" -s "release-$NEW_VERSION"
git push origin "release-$NEW_VERSION"

# Actually deploy.
mvn clean source:jar javadoc:jar verify deploy:deploy -DperformRelease=true

# Workaround a problem with markdown translation
# ( https:// stackoverflow.com/questions/36708241 )
mvn -f rule verify javadoc:javadoc site
find "$RELEASE_CLONE/rule/target/site" -name \*.html \
    | xargs perl -i -pe 's/(href="[^"#?]*)\.md(#[^"]*)?(")/$1.html$2$3/g'

# Publish the site
cd ~/work
export SITE_CLONE="$PWD/fencesrule-site"

rm -rf "$SITE_CLONE" \
&& cd "$(dirname "$SITE_CLONE")" \
&& git clone -b gh-pages git@github.com:mikesamuel/fences-maven-enforcer-rule.git \
       "$(basename "$SITE_CLONE")" \
&& cd "$SITE_CLONE"

# Empty all source files.  Later we will git rm any that were not copied
# from site.
find . -type f -not -path ./.git/\* -exec rm '{}' \; -exec touch '{}' \;

cp -r "$RELEASE_CLONE"/rule/target/site/* "$SITE_CLONE"/

find . -type f -not -path ./.git/\* -exec git add '{}' \;
find . -size 0 -not -path ./.git/\* -exec git rm -f '{}' \;

git commit -m "publish site for $NEW_VERSION"
git push origin gh-pages


# Bump the development version.
cd "$RELEASE_CLONE"
for ph in $(find . -name pom.xml.placeholder); do
    cp "$ph" "$(dirname "$ph")"/"$(basename "$ph" .placeholder)"
done
find . -name pom.xml \
    | xargs perl -i.placeholder \
            -pe "s/$VERSION_PLACEHOLDER/$NEW_DEV_VERSION/"
perl -i -pe "s|<project-under-test.version>.*?</project-under-test.version>|<project-under-test.version>$NEW_DEV_VERSION</project-under-test.version>|" \
     "$RELEASE_CLONE/rule/src/it/resources/pom.xml"
find . -name pom.xml.placeholder | xargs rm

git diff

git commit -am "Bumped dev version"

git push origin master

# Now Release
echo '1. Go to oss.sonatype.org'
echo '2. Look under staging repositories for one named'
echo '   comgooglesecurity-fences-maven-enforcer-rule-...'
echo '3. Close it.'
echo '4. Refresh until it is marked "Closed".'
echo '5. Check that its OK.'
echo '6. Release it.'
