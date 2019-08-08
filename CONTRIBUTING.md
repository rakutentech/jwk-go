# Contributing to Rakuten Ecosystem Projects

Thank you for taking time to contribute code to one of our projects.

We love getting contribution and feedback from the community, and we want to
make this process as simple as possible, so we try to make the number of
hurdles as minimum as possible. That being said, we do have some guidelines

## Contribution Guidelines

### Pull Request

Please open a pull request with the branch that contains the code you want to
contribute. The pull request should include a proper description of the bug
you're fixing and the feature you're adding, as well as all relevant
technical details (e.g. adding a new dependency).

## Coding Style

For Go code, please make sure your code follows the Effective Go style and
passes go vet. We also run gometalinter on our code, but some of the warning
types are ignored.

## Unit Tests

All new features should come with unit tests. We're using Gingkgo and Gomega
for testing.

