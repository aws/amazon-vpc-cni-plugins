# amazon-vpc-cni-plugins

## Included tests

There are two different kinds of tests that are included with this repository, unit tests and end to end tests.

## Basic setup

There is some tooling that needs to be in place for the tests to be able to run, the basics are listed below

- Git - you can install either the `build-essentials` meta package on Debian based distros or the package group called `'Development Tools'` on RHEL based distros and that will get you `git`. Otherwise, you can install Git separately as well.
- Make - the above meta package/package group will also include `make` but it can also be installed separately.
- Go - go can be installed from the golang website; the tests are confirmed working on Go version 1.19
- `iptables` - in case the tests are being run in a minimal environment, `iptables` can be obtained from the default package manager for the distro; it might also come installed already on the system

For the end to end tests, a successful build is also required. A build can be triggered by running `make build`.

## Running

The unit tests can be run using `make unit-test` and the end to end tests can be run using `make e2e-test`.

There are also some specific Make targets included to help with more directed testing. These are included in the table below

| Target                         | Description                                                   |
| ------------------------------ | ------------------------------------------------------------- |
| `appmesh-unit-test`            | Run only the `aws-appmesh` plugin unit tests                  |
| `ecs-serviceconnect-unit-test` | Run only the `ecs-serviceconnect` plugin unit tests           |
| `vpc-branch-eni-e2e-tests`     | Run only the the `vpc-branch-eni` plugin end to end tests     |
| `vpc-tunnel-e2e-tests`         | Run only the the `vpc-tunnel` plugin end to end tests         |
| `appmesh-e2e-tests`            | Run only the the `aws-appmesh` plugin end to end tests        |
| `ecs-serviceconnect-e2e-test`  | Run only the the `ecs-serviceconnect` plugin end to end tests |

## Debugging

If you're running VS Code, here is a sample `launch.json` that can help set up debugging for the tests. Something to note is that since these tests run with elevated privileges, it is always a good idea to not stop a test in the middle of execution because it might leave behind resources that need cleaned up.

```json
{
  // Use IntelliSense to learn about possible attributes.
  // Hover to view descriptions of existing attributes.
  // For more information, visit: https://go.microsoft.com/fwlink/?linkid=830387
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Debug e2e test",
      "type": "go",
      "request": "launch",
      "mode": "auto",
      "program": "${fileDirname}",
      "asRoot": true,
      "console": "integratedTerminal",
      "buildFlags": "-tags=e2e_test",
      "env": {
        "CNI_PATH": "${input:computedCniPath}"
      }
    }
  ],
  "inputs": [
    {
      "id": "computedCniPath",
      "description": "Optional, the path to the CNI plugin build in case the OS or the arch are different.",
      "type": "promptString",
      "default": "${workspaceFolder}${pathSeparator}build${pathSeparator}linux_amd64"
    }
  ]
}
```
