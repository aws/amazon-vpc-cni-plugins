## Amazon vpc-bridge CNI plugin
vpc-bridge CNI plugin for EKS Windows.

## Pre-requisites for running vpc-bridge CNI plugin for EKS Windows
1. Env variable  `AWS_VPC_CNI_K8S_CONNECTOR_BINARY_PATH` is required to be set. This will be already set in EKS Windows Optimized AMIs.
Set env variable `AWS_VPC_CNI_K8S_CONNECTOR_BINARY_PATH` to `C:\Program Files\Amazon\EKS\bin\aws-vpc-cni-k8s-connector.exe`.
