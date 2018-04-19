# iam4kube

iam4kube allows containers running on Kubernetes to transparently use credentials for an IAM role as if the code
is being executed on an AWS EC2 instance. This is achieved by emulating a
[subset of the AWS Metadata API](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html#instance-metadata-security-credentials).

## Features / implementation decisions

### Core features

- IAM roles from other AWS accounts are fully supported. Specifying full ARN of the role is always required;
- IAM role ARN is attached as `iam.amazonaws.com/roleArn`
  [annotation](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/) on
  [`ServiceAccount`](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/) and all
  [`Pod`](https://kubernetes.io/docs/concepts/workloads/pods/pod/)s that use it share the same credentials;
- Credentials are eagerly prefetched and refreshed to ensure really fast (<10ms) response times. This ensures AWS SDKs
  which typically have very aggressive timeouts do not... time out;
- [Prometheus](https://prometheus.io/) metrics - de-facto standard in Kubernetes ecosystem;
- Supports metadata endpoint for fetching availability zone / region where container is running;
- Supports [External ID](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html).
  It can be specified using `iam.amazonaws.com/roleExternalId` annotation on `ServiceAccount`.
- Configurable rate limiting. Defaults to 10 AWS STS requests / second with bursts up to 20 / second;
- Smart [readiness check](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-probes/#define-readiness-probes)
  to avoid empty cache hits. Only reports ready once cache has been fully populated with credentials;
- [STS session name](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html) is supported and is
  set to "namespace@name" of the `ServiceAccount` for traceability via
  [AWS CloudTrail](https://aws.amazon.com/cloudtrail/);
- Structured JSON logging.

### Race-proof implementation

Kubernetes is a distributed system by itself. The following situations are possible:
1. A container can start and try to fetch credentials before iam4kube (or anything else really)
   observes that there is such Pod;
1. Same with `ServiceAccount`. A `Pod` that uses it may be created really quickly and in a busy cluster information
   about the `ServiceAccount` may not be instantaneously available to iam4kube;
1. Credentials may not be available yet (still being fetched) when a request for them comes in;
1. Annotation with IAM role ARN on an existing `ServiceAccount` may be set, then a `Pod` that uses it starts up quickly
   but iam4kube may have not seen the annotation update yet (still has `ServiceAccount` without the
   annotation in the cache).

These kinds of situations are handled gracefully by not responding to a request for credentials and waiting for
missing pieces of information to become available. Request may either time out (15 seconds currently) or be aborted by
the client. The waiting is implemented as efficiently as possible, without any internal (within the program) or
external polling to ensure lowest response latency and no overhead.

### Security

iam4kube should be run on a set of nodes where no other workloads are scheduled. This set of nodes should
have extended IAM permissions to assume various IAM roles to fetch required credentials. All other nodes (worker nodes)
that need AWS IAM credentials should not have such permissions so that if container boundaries are breached
malicious code does not have access to the powerful IAM permissions.

Because of this design decision it is out of scope of iam4kube to configure ip tables / IPVS to correctly route traffic
from worker nodes to it. We may have a separate program for doing this here in the same repository later.

iam4kube should be deployed using a `Deployment` behind a `Service`. This, combined with smart readiness check, allows
to easily perform zero downtime upgrades unlike if it is run as a `DeamonSet` on each node.

Only a subset of metadata api is implemented, no requests are proxied directly to the actual metadata service.
This is by design. Consider the issue of the opposite approach: tomorrow AWS might add an endpoint that exposes some
sensitive information - that would create a security hole. Also there is plenty of information that would most likely
be incorrect for the container because it might be running on a different host.
