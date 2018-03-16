#!/bin/bash

docker login -u "$DOCKER_USERNAME" -p "$DOCKER_PASSWORD"
docker tag couchbase/sdk-doctor:${TRAVIS_BUILD_NUMBER} couchbase/sdk-doctor:${TRAVIS_TAG}
docker tag couchbase/sdk-doctor:${TRAVIS_BUILD_NUMBER} couchbase/sdk-doctor:latest
docker push couchbase/sdk-doctor:${TRAVIS_TAG}
docker push couchbase/sdk-doctor:latest