# Crazy Train demo deployment

## AWS Environment

Get a blank AWS environment and be sure to have the `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.

Je configure la CLI AWS.

```sh
ENV_NAME=open-tour-2024
mkdir -p ~/tmp/$ENV_NAME/.aws
cd ~/tmp/$ENV_NAME
export AWS_CONFIG_FILE=$HOME/tmp/$ENV_NAME/.aws/config
export AWS_SHARED_CREDENTIALS_FILE=$HOME/tmp/$ENV_NAME/.aws/credentials
aws configure
```

## OpenShift

Je trouve la dernière version stable à partir du [repository cincinnati](https://github.com/openshift/cincinnati-graph-data/tree/master/channels).

Téléchargement de la CLI OpenShift **multi architecture**.

```sh
OPENSHIFT_VERSION=4.16.20
curl -sfL https://mirror.openshift.com/pub/openshift-v4/multi/clients/ocp/$OPENSHIFT_VERSION/amd64/openshift-install-linux.tar.gz | tar -zx -C ~/local/bin openshift-install
curl -sfL https://mirror.openshift.com/pub/openshift-v4/multi/clients/ocp/$OPENSHIFT_VERSION/amd64/openshift-client-linux-$OPENSHIFT_VERSION.tar.gz | tar -zx -C ~/local/bin oc kubectl
```

Fichier **install-config.yaml** :

```yaml
additionalTrustBundlePolicy: Proxyonly
apiVersion: v1
baseDomain: sandbox1730.opentlc.com
compute:
- architecture: amd64
  hyperthreading: Enabled
  name: worker
  platform:
    aws:
      type: m5a.2xlarge
      zones:
      - eu-west-3a
      - eu-west-3b
      - eu-west-3c
  replicas: 3
controlPlane:
  architecture: amd64
  hyperthreading: Enabled
  name: master
  platform:
    aws:
      rootVolume:
        iops: 4000
        size: 500
        type: io1
      type: m5a.2xlarge
      zones:
      - eu-west-3a
      - eu-west-3b
      - eu-west-3c
  replicas: 3
metadata:
  creationTimestamp: null
  name: crazy-train
networking:
  clusterNetwork:
  - cidr: 10.128.0.0/14
    hostPrefix: 23
  machineNetwork:
  - cidr: 10.0.0.0/16
  networkType: OVNKubernetes
  serviceNetwork:
  - 172.30.0.0/16
platform:
  aws:
    region: eu-west-3
publish: External
pullSecret: 'REDACTED XXX REDACTED XXX'
sshKey: |
  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFW62WJXI1ZCMfNA4w0dMpL0fsldhbEfULNGIUB0nQui nmasse@localhost.localdomain
```

Générer les manifests.

```sh
openshift-install create manifests --dir .
```

Comme la [documentation OpenShift](https://docs.openshift.com/container-platform/4.17/post_installation_configuration/configuring-multi-arch-compute-machines/multi-architecture-configuration.html) indique que le **Cluster Samples Operator** n'est pas compatible multi-architecture, je dois le désactiver via les [cluster capabilities](https://docs.openshift.com/container-platform/4.17/post_installation_configuration/enabling-cluster-capabilities.html).

Editer le fichier **manifests/cvo-overrides.yaml**.

```yaml
apiVersion: config.openshift.io/v1
kind: ClusterVersion
metadata:
  namespace: openshift-cluster-version
  name: version
spec:
  channel: stable-4.17
  clusterID: 09bd5ac7-abe8-4bab-b6ea-5e4525c2483a
  baselineCapabilitySet: None
  additionalEnabledCapabilities:
  - marketplace
  - MachineAPI
  - Console
  - Insights
  - Storage
  - CSISnapshot
  - NodeTuning
  - ImageRegistry
  - OperatorLifecycleManager
  - Build
  - DeploymentConfig
```

Lancer l'installation du cluster.

```sh
openshift-install create cluster --dir . --log-level=info
```

Résultat :

```
INFO Consuming Openshift Manifests from target directory
INFO Consuming Common Manifests from target directory
INFO Consuming OpenShift Install (Manifests) from target directory
INFO Consuming Worker Machines from target directory
INFO Consuming Master Machines from target directory
INFO Credentials loaded from the "default" profile in file "/home/nmasse/tmp/open-tour-2024/.aws/credentials"
INFO Creating infrastructure resources...
INFO Reconciling IAM roles for control-plane and compute nodes
INFO Creating IAM role for master
INFO Creating IAM role for worker
INFO Started local control plane with envtest
INFO Stored kubeconfig for envtest in: /home/nmasse/tmp/open-tour-2024/cluster/.clusterapi_output/envtest.kubeconfig
INFO Running process: Cluster API with args [-v=2 --diagnostics-address=0 --health-addr=127.0.0.1:39497 --webhook-port=42731 --webhook-cert-dir=/tmp/envtest-serving-certs-1903053482 --kubeconfig=/home/nmasse/tmp/open-tour-2024/cluster/.clusterapi_output/envtest.kubeconfig]
INFO Running process: aws infrastructure provider with args [-v=4 --diagnostics-address=0 --health-addr=127.0.0.1:35517 --webhook-port=35961 --webhook-cert-dir=/tmp/envtest-serving-certs-3213588306 --feature-gates=BootstrapFormatIgnition=true,ExternalResourceGC=true,TagUnmanagedNetworkResources=false,EKS=false --kubeconfig=/home/nmasse/tmp/open-tour-2024/cluster/.clusterapi_output/envtest.kubeconfig]
INFO Created manifest *v1.Namespace, namespace= name=openshift-cluster-api-guests
INFO Created manifest *v1beta2.AWSClusterControllerIdentity, namespace= name=default
INFO Created manifest *v1beta1.Cluster, namespace=openshift-cluster-api-guests name=crazy-train-xqr2h
INFO Created manifest *v1beta2.AWSCluster, namespace=openshift-cluster-api-guests name=crazy-train-xqr2h
INFO Waiting up to 15m0s (until 12:26PM CET) for network infrastructure to become ready...
INFO Network infrastructure is ready
INFO Creating private Hosted Zone
INFO Creating Route53 records for control plane load balancer
INFO Created manifest *v1beta2.AWSMachine, namespace=openshift-cluster-api-guests name=crazy-train-xqr2h-bootstrap
INFO Created manifest *v1beta2.AWSMachine, namespace=openshift-cluster-api-guests name=crazy-train-xqr2h-master-0
INFO Created manifest *v1beta2.AWSMachine, namespace=openshift-cluster-api-guests name=crazy-train-xqr2h-master-1
INFO Created manifest *v1beta2.AWSMachine, namespace=openshift-cluster-api-guests name=crazy-train-xqr2h-master-2
INFO Created manifest *v1beta1.Machine, namespace=openshift-cluster-api-guests name=crazy-train-xqr2h-bootstrap
INFO Created manifest *v1beta1.Machine, namespace=openshift-cluster-api-guests name=crazy-train-xqr2h-master-0
INFO Created manifest *v1beta1.Machine, namespace=openshift-cluster-api-guests name=crazy-train-xqr2h-master-1
INFO Created manifest *v1beta1.Machine, namespace=openshift-cluster-api-guests name=crazy-train-xqr2h-master-2
INFO Created manifest *v1.Secret, namespace=openshift-cluster-api-guests name=crazy-train-xqr2h-bootstrap
INFO Created manifest *v1.Secret, namespace=openshift-cluster-api-guests name=crazy-train-xqr2h-master
INFO Waiting up to 15m0s (until 12:31PM CET) for machines [crazy-train-xqr2h-bootstrap crazy-train-xqr2h-master-0 crazy-train-xqr2h-master-1 crazy-train-xqr2h-master-2] to provision...
INFO Control-plane machines are ready
INFO Cluster API resources have been created. Waiting for cluster to become ready...
INFO Consuming Cluster API Manifests from target directory
INFO Consuming Cluster API Machine Manifests from target directory
INFO Waiting up to 20m0s (until 12:37PM CET) for the Kubernetes API at https://api.crazy-train.sandbox1730.opentlc.com:6443...
INFO API v1.29.9+5865c5b up
INFO Waiting up to 45m0s (until 1:05PM CET) for bootstrapping to complete...
INFO Destroying the bootstrap resources...
INFO Waiting up to 5m0s for bootstrap machine deletion openshift-cluster-api-guests/crazy-train-xqr2h-bootstrap...
INFO Shutting down local Cluster API controllers...
INFO Stopped controller: Cluster API
INFO Stopped controller: aws infrastructure provider
INFO Shutting down local Cluster API control plane...
INFO Local Cluster API system has completed operations
INFO Finished destroying bootstrap resources
INFO Waiting up to 40m0s (until 1:13PM CET) for the cluster at https://api.crazy-train.sandbox1730.opentlc.com:6443 to initialize...
INFO Waiting up to 30m0s (until 1:13PM CET) to ensure each cluster operator has finished progressing...
INFO All cluster operators have completed progressing
INFO Checking to see if there is a route at openshift-console/console...
INFO Install complete!
INFO To access the cluster as the system:admin user when using 'oc', run 'export KUBECONFIG=/home/nmasse/tmp/open-tour-2024/cluster/auth/kubeconfig'
INFO Access the OpenShift web-console here: https://console-openshift-console.apps.crazy-train.sandbox1730.opentlc.com
INFO Login to the console with user: "kubeadmin", and password: "REDACTED"
INFO Time elapsed: 33m3s
```

D'après la [documentation multi-architecture](https://docs.openshift.com/container-platform/4.14/post_installation_configuration/configuring-multi-arch-compute-machines/creating-multi-arch-compute-nodes-aws.html#creating-multi-arch-compute-nodes-aws) il y a des vérifications à faire :

```
$ export KUBECONFIG=/home/nmasse/tmp/open-tour-2024/cluster/auth/kubeconfig
$ oc adm release info -o jsonpath="{ .metadata.metadata}"

{"release.openshift.io/architecture":"multi","url":"https://access.redhat.com/errata/RHSA-2024:8683"}

$ oc get configmap/coreos-bootimages -n openshift-machine-config-operator -o jsonpath='{.data.stream}' | jq -r '.architectures.aarch64.images.aws.regions."eu-west-3".image'
ami-04089c594abca8e13

$ oc get -o jsonpath='{.status.infrastructureName}{"\n"}' infrastructure cluster
crazy-train-xqr2h
```

Pour ajouter un noeud au cluster Red Hat OpenShift :

```sh
ARCH="aarch64" # x86_64 or aarch64
AWS_REGION="eu-west-3"
AWS_AZ=("a" "b" "c")
AWS_INSTANCE_TYPE="m6g.2xlarge"
AMI_ID="$(oc get configmap/coreos-bootimages -n openshift-machine-config-operator -o jsonpath='{.data.stream}' | jq -r ".architectures.$ARCH.images.aws.regions.\"$AWS_REGION\".image")"
INFRASTRUCTURE_NAME="$(oc get -o jsonpath='{.status.infrastructureName}' infrastructure cluster)"
for az in "${AWS_AZ[@]}"; do
  oc apply -f - <<EOF
apiVersion: machine.openshift.io/v1beta1
kind: MachineSet
metadata:
  name: $INFRASTRUCTURE_NAME-$ARCH-worker-$AWS_REGION$az
  namespace: openshift-machine-api
  labels:
    machine.openshift.io/cluster-api-cluster: $INFRASTRUCTURE_NAME
spec:
  replicas: 0
  selector:
    matchLabels:
      machine.openshift.io/cluster-api-cluster: $INFRASTRUCTURE_NAME
      machine.openshift.io/cluster-api-machineset: $INFRASTRUCTURE_NAME-$ARCH-worker-$AWS_REGION$az
  template:
    metadata:
      labels:
        machine.openshift.io/cluster-api-cluster: $INFRASTRUCTURE_NAME
        machine.openshift.io/cluster-api-machine-role: worker
        machine.openshift.io/cluster-api-machine-type: worker
        machine.openshift.io/cluster-api-machineset: $INFRASTRUCTURE_NAME-$ARCH-worker-$AWS_REGION$az
    spec:
      lifecycleHooks: {}
      metadata:
        labels:
          node-role.kubernetes.io/worker: ''
          emea-open-demo.redhat.com/arm64-architecture: ''
      providerSpec:
        value:
          userDataSecret:
            name: worker-user-data
          placement:
            availabilityZone: $AWS_REGION$az
            region: $AWS_REGION
          credentialsSecret:
            name: aws-cloud-credentials
          instanceType: $AWS_INSTANCE_TYPE
          metadata:
            creationTimestamp: null
          blockDevices:
            - ebs:
                encrypted: true
                iops: 0
                kmsKey:
                  arn: ''
                volumeSize: 120
                volumeType: gp3
          securityGroups:
            - filters:
                - name: 'tag:Name'
                  values:
                    - $INFRASTRUCTURE_NAME-node
            - filters:
                - name: 'tag:Name'
                  values:
                    - $INFRASTRUCTURE_NAME-lb
          kind: AWSMachineProviderConfig
          metadataServiceOptions: {}
          tags:
            - name: kubernetes.io/cluster/$INFRASTRUCTURE_NAME
              value: owned
          deviceIndex: 0
          ami:
            id: $AMI_ID
          subnet:
            filters:
              - name: 'tag:Name'
                values:
                  - $INFRASTRUCTURE_NAME-subnet-private-$AWS_REGION$az
          apiVersion: machine.openshift.io/v1beta1
          iamInstanceProfile:
            id: $INFRASTRUCTURE_NAME-worker-profile
      taints:
      - key: emea-open-demo.redhat.com/arm64-architecture
        effect: NoSchedule
EOF
done
```

Ça fonctionne.

```
$ oc -n openshift-machine-api scale machineset $INFRASTRUCTURE_NAME-$ARCH-worker-${AWS_REGION}a --replicas=1

machineset.machine.openshift.io/crazy-train-64d8v-aarch64-worker-eu-west-3a scaled
```

**Suppression de l'utilisateur kubeadmin**

```sh
oc delete secrets kubeadmin -n kube-system
```

**Ajout des noeuds avec GPU**

```sh
ARCH="x86_64" # x86_64 or aarch64
AWS_REGION="eu-west-3"
AWS_AZ=("a" "b" "c")
AWS_INSTANCE_TYPE="g4dn.2xlarge"
AMI_ID="$(oc get configmap/coreos-bootimages -n openshift-machine-config-operator -o jsonpath='{.data.stream}' | jq -r ".architectures.$ARCH.images.aws.regions.\"$AWS_REGION\".image")"
INFRASTRUCTURE_NAME="$(oc get -o jsonpath='{.status.infrastructureName}' infrastructure cluster)"
for az in "${AWS_AZ[@]}"; do
  oc apply -f - <<EOF
apiVersion: machine.openshift.io/v1beta1
kind: MachineSet
metadata:
  name: $INFRASTRUCTURE_NAME-gpu-worker-$AWS_REGION$az
  namespace: openshift-machine-api
  labels:
    machine.openshift.io/cluster-api-cluster: $INFRASTRUCTURE_NAME
spec:
  replicas: 0
  selector:
    matchLabels:
      machine.openshift.io/cluster-api-cluster: $INFRASTRUCTURE_NAME
      machine.openshift.io/cluster-api-machineset: $INFRASTRUCTURE_NAME-$ARCH-worker-$AWS_REGION$az
  template:
    metadata:
      labels:
        machine.openshift.io/cluster-api-cluster: $INFRASTRUCTURE_NAME
        machine.openshift.io/cluster-api-machine-role: worker
        machine.openshift.io/cluster-api-machine-type: worker
        machine.openshift.io/cluster-api-machineset: $INFRASTRUCTURE_NAME-$ARCH-worker-$AWS_REGION$az
    spec:
      lifecycleHooks: {}
      metadata:
        labels:
          node-role.kubernetes.io/worker: ''
          nvidia.com/gpu: ''
      providerSpec:
        value:
          userDataSecret:
            name: worker-user-data
          placement:
            availabilityZone: $AWS_REGION$az
            region: $AWS_REGION
          credentialsSecret:
            name: aws-cloud-credentials
          instanceType: $AWS_INSTANCE_TYPE
          metadata:
            creationTimestamp: null
          blockDevices:
            - ebs:
                encrypted: true
                iops: 0
                kmsKey:
                  arn: ''
                volumeSize: 120
                volumeType: gp3
          securityGroups:
            - filters:
                - name: 'tag:Name'
                  values:
                    - $INFRASTRUCTURE_NAME-node
            - filters:
                - name: 'tag:Name'
                  values:
                    - $INFRASTRUCTURE_NAME-lb
          kind: AWSMachineProviderConfig
          metadataServiceOptions: {}
          tags:
            - name: kubernetes.io/cluster/$INFRASTRUCTURE_NAME
              value: owned
          deviceIndex: 0
          ami:
            id: $AMI_ID
          subnet:
            filters:
              - name: 'tag:Name'
                values:
                  - $INFRASTRUCTURE_NAME-subnet-private-$AWS_REGION$az
          apiVersion: machine.openshift.io/v1beta1
          iamInstanceProfile:
            id: $INFRASTRUCTURE_NAME-worker-profile
      taints:
      - key: nvidia.com/gpu
        effect: NoSchedule
EOF
done
```

Puis monter les replicas à 1 :

```sh
for az in "${AWS_AZ[@]}"; do
  oc scale -n openshift-machine-api "MachineSet/$INFRASTRUCTURE_NAME-gpu-worker-$AWS_REGION$az" --replicas=1
done
```

**Configuration de l'authentification Google**

Il faut ajouter l'URL `https://oauth-openshift.apps.crazy-train.sandbox1730.opentlc.com/oauth2callback/RedHatSSO` au [projet Google](https://console.cloud.google.com/apis/credentials?project=nmasse-ocp).

```sh
export GOOGLE_CLIENT_SECRET=REDACTED
export GOOGLE_CLIENT_ID=REDACTED
oc create secret generic redhat-sso-client-secret -n openshift-config --from-literal="clientSecret=$GOOGLE_CLIENT_SECRET"
oc apply -f - <<EOF
apiVersion: config.openshift.io/v1
kind: OAuth
metadata:
  name: cluster
spec:
  identityProviders:
  - google:
      clientID: "$GOOGLE_CLIENT_ID"
      clientSecret:
        name: redhat-sso-client-secret
      hostedDomain: redhat.com
    mappingMethod: claim
    name: RedHatSSO
    type: Google
EOF
oc apply -f - <<EOF
apiVersion: user.openshift.io/v1
kind: Group
metadata:
  name: demo-admins
users:
- nmasse@redhat.com
- alegros@redhat.com
- mouachan@redhat.com
EOF
oc adm policy add-cluster-role-to-group cluster-admin demo-admins
```

**Let's Encrypt**

```sh
# Cluster DNS domain
export DOMAIN=crazy-train.sandbox1730.opentlc.com

# Get a valid certificate
sudo dnf install -y golang-github-acme-lego
lego -d "api.$DOMAIN" -d "*.apps.$DOMAIN" -a -m nmasse@redhat.com --dns route53 run

# Install it on the router
kubectl create secret tls router-certs-$(date "+%Y-%m-%d") --cert=".lego/certificates/api.$DOMAIN.crt" --key=".lego/certificates/api.$DOMAIN.key" -n openshift-ingress --dry-run -o yaml > router-certs.yaml
kubectl apply -f "router-certs.yaml" -n openshift-ingress
kubectl patch ingresscontroller default -n openshift-ingress-operator --type=merge --patch-file=/dev/fd/0 <<EOF
{"spec": { "defaultCertificate": { "name": "router-certs-$(date "+%Y-%m-%d")" }}}
EOF
```

**Installation de Tekton**

```yaml
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: openshift-pipelines-operator
  namespace: openshift-operators
spec:
  channel: latest
  name: openshift-pipelines-operator-rh
  source: redhat-operators
  sourceNamespace: openshift-marketplace
```

**Stockage AWS EFS**

```yaml
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: aws-efs-csi-driver-operator
  namespace: openshift-cluster-csi-drivers
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: aws-efs-csi-driver-operator
  namespace: openshift-cluster-csi-drivers
spec:
  channel: stable
  installPlanApproval: Automatic
  name: aws-efs-csi-driver-operator
  source: redhat-operators
  sourceNamespace: openshift-marketplace
---
apiVersion: operator.openshift.io/v1
kind: ClusterCSIDriver
metadata:
    name: efs.csi.aws.com
spec:
  managementState: Managed
```

Créer un volume EFS en suivant les étapes décrites dans la [documentation AWS](https://docs.aws.amazon.com/efs/latest/ug/gs-step-two-create-efs-resources.html).

![Console EFS](./2024-08%20AWS%20Console%20EFS.png)

Créer la **StorageClass** associée au volume EFS.

```yaml
kind: StorageClass
apiVersion: storage.k8s.io/v1
metadata:
  name: efs-csi
provisioner: efs.csi.aws.com
parameters:
  provisioningMode: efs-ap
  fileSystemId: fs-027c702d51987f483
  directoryPerms: "700"
  basePath: "/pv"
  uid: "0"
  gid: "0"
```

En suivant la documentation [OpenShift 4.15](https://docs.openshift.com/container-platform/4.15/storage/container_storage_interface/persistent-storage-csi-aws-efs.html#efs-create-volume_persistent-storage-csi-aws-efs), modifier le **Security Group** EFS pour autoriser les noeuds OpenShift à accéder au stockage via le protocole NFS.

On the [EFS console](https://console.aws.amazon.com/efs) :

1. On the **Network** tab, copy the Security Group ID (you will need this in the next step).
2. Go to [Security Groups](https://console.aws.amazon.com/ec2/v2/home#SecurityGroups), and find the Security Group used by the EFS volume.
3. On the **Inbound rules** tab, click **Edit inbound rules**, and then add a new rule with the following settings to allow OpenShift Container Platform nodes to access EFS volumes :
    - **Type**: NFS
    - **Protocol**: TCP
    - **Port range**: 2049
    - **Source**: Custom/IP address range of your nodes (for example: “10.0.0.0/16”)

![Security Group for EFS](./2024-08%20AWS%20Console%20-%20Security%20Group%20for%20EFS.png)

Désactiver l’**affinity-assistant** dans la configuration Tekton.

```sh
oc patch configmap/feature-flags -n openshift-pipelines --type=merge -p '{"data":{"disable-affinity-assistant":"true"}}'
```

**Authentication à Quay.io**

```sh
oc new-project build-multiarch
oc create secret docker-registry quay-authentication --docker-email=nmasse@redhat.com --docker-username=nmasse_itix --docker-password=REDACTED --docker-server=quay.io
oc annotate secret/quay-authentication tekton.dev/docker-0=https://quay.io
```

**Création des pipelines CI/CD**

```sh
git clone https://github.com/nmasse-itix/tekton-pipeline-multiarch
cd tekton-pipeline-multiarch
oc apply -k tekton/
for yaml in examples/*/tekton/pipeline.yaml; do oc apply -f $yaml; done
```

**Démarrer les pipelines CI/CD**

```sh
for yaml in examples/*/tekton/pipelinerun.yaml; do oc create -f $yaml; done
```

**Installer AMQ Streams**

```yaml
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: amq-streams
  namespace: openshift-operators
spec:
  channel: stable
  name: amq-streams
  source: redhat-operators
  sourceNamespace: openshift-marketplace
```

**Installation de ArgoCD**

```yaml
apiVersion: v1
kind: Namespace
metadata:
  labels:
    kubernetes.io/metadata.name: openshift-gitops-operator
  name: openshift-gitops-operator
spec:
  finalizers:
  - kubernetes
---
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: openshift-gitops-operator
  namespace: openshift-gitops-operator
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: openshift-gitops-operator
  namespace: openshift-gitops-operator
spec:
  channel: latest
  name: openshift-gitops-operator
  source: redhat-operators
  sourceNamespace: openshift-marketplace
```

Fix its configuration.

```sh
oc patch argocd openshift-gitops -n openshift-gitops -p '{"spec":{"server":{"insecure":true,"route":{"enabled": true,"tls":{"termination":"edge","insecureEdgeTerminationPolicy":"Redirect"}}}}}' --type=merge
oc patch argocd openshift-gitops -n openshift-gitops -p '{"spec":{"applicationInstanceLabelKey":"argocd.argoproj.io/instance"}}' --type=merge
```

Give cluster-admin access rights to the **OpenShift Gitops** operator.

```shell
oc adm policy add-cluster-role-to-user cluster-admin system:serviceaccount:openshift-gitops:openshift-gitops-argocd-application-controller
```

**Installer le WebTerminal**

```yaml
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: web-terminal
  namespace: openshift-operators
spec:
  channel: fast
  name: web-terminal
  source: redhat-operators
  sourceNamespace: openshift-marketplace
```

**Installer un serveur Nexus**

```yaml
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: nexus-repository-ha-operator-certified
  namespace: openshift-operators
spec:
  channel: stable
  name: nexus-repository-ha-operator-certified
  source: certified-operators
  sourceNamespace: openshift-marketplace
---
apiVersion: v1
kind: Namespace
metadata:
  labels:
    kubernetes.io/metadata.name: nexus
  name: nexus
spec:
  finalizers:
  - kubernetes
---
apiVersion: sonatype.com/v1alpha1
kind: NexusRepo
metadata:
  name: maven
  namespace: nexus
spec:
  ingress:
    enabled: false
    dockerSubdomain: false
    annotations: null
    host: example.com
    name: nexus-ingress
    additionalRules: null
    dockerIngress:
      annotations: null
      enabled: false
      host: example.com
      name: nexus-docker-ingress
    tls:
      enabled: false
      secretName: tlsSecretName
    defaultRule: false
  license:
    fileContentsBase64: your_license_file_contents_in_base_64
    secretName: nexus-repo-license
  nexusData:
    pvc:
      accessMode: ReadWriteOnce
      size: 2Gi
    storageClass:
      enabled: false
      name: nexusrepo-storage
      parameters: {}
      provisioner: provisioner
      reclaimPolicy: Retain
      volumeBindingMode: WaitForFirstConsumer
    volumeClaimTemplate:
      enabled: false
  secret:
    nexusSecret:
      enabled: false
      mountPath: /var/nexus-repo-secrets
      name: nexus-secret.json
      nexusSecretsKeyId: super_secret_key_id
      secretKeyfileContentsBase64: secretKeyfileContentsBase64
  service:
    docker:
      enabled: false
      name: nexus-repo-docker-service
      port: 9090
      protocol: TCP
      targetPort: 9090
      type: NodePort
    nexus:
      enabled: true
      name: maven-repository
      port: 80
      protocol: TCP
      targetPort: 8081
      type: ClusterIP
  statefulset:
    container:
      containerPort: 8081
      env:
        clustered: false
        install4jAddVmParams: '-Xms2703m -Xmx2703m'
        jdbcUrl: null
        nexusInitialPassword: R3dH4tAdm1n!
        password: nexus
        user: nexus
        zeroDowntimeEnabled: false
      imageName: 'registry.connect.redhat.com/sonatype/nexus-repository-manager@sha256:ee153ccfa1132e92a5467493903ebd4a6e64c4cc7bbca59617ff1c9c2b917a0a'
      pullPolicy: IfNotPresent
      resources:
        limits:
          cpu: 4
          memory: 8Gi
        requests:
          cpu: 1
          memory: 2Gi
      terminationGracePeriod: 120
    imagePullSecrets: {}
    livenessProbe:
      failureThreshold: 6
      initialDelaySeconds: 240
      path: /
      periodSeconds: 60
    name: nexusrepo-statefulset
    readinessProbe:
      failureThreshold: 6
      initialDelaySeconds: 240
      path: /
      periodSeconds: 60
    replicaCount: 1
---
kind: Route
apiVersion: route.openshift.io/v1
metadata:
  name: nexus-console
  namespace: nexus
spec:
  to:
    kind: Service
    name: nxrm-ha-maven-repository
    weight: 100
  port:
    targetPort: '8081'
  tls:
    termination: edge
    insecureEdgeTerminationPolicy: Redirect
  wildcardPolicy: None
```

Configuration post-install :

- Au démarrage du Nexus, activer l'accès anonyme.
- Créer un repo **public** de type **proxy** qui pointe sur `https://maven.repository.redhat.com/ga/`. Version policy: **Release**, Layout policy: **Permissive**.
- Créer un repo **early-access** de type **proxy** qui pointe sur `https://maven.repository.redhat.com/earlyaccess/all/`. Version policy: **Release**, Layout policy: **Permissive**.
- Créer un repo **redhat** de type **group** qui inclue les repos **public** et **early-access**. Version policy: **Mixed**, Layout policy: **Permissive**.
- Créer un repo **apache.org-proxy** de type **proxy** qui pointe sur `https://repo.maven.apache.org/maven2/`. Cliquer sur **View certificate**, puis **Add to truststore**. Cocher la case **Use certificates stores to...**. Version policy: **Mixed**, Layout policy: **Strict**.
- Créer un repo **central** de type **group** qui inclue le repo **apache.org-proxy**. Version policy: **Mixed**, Layout policy: **Strict**.

> [!WARNING]
> Si les artefacts n'arrivent pas en cache, le mieux est de supprimer tous les repos et de tout recréer.

Configuration des fichiers **pom.xml** dans le monorepo applicatif en listant les repo publics.

```xml
  <repositories>
    <repository>
      <id>central</id>
      <url>https://repo.maven.apache.org/maven2/</url>
      <releases>
        <enabled>true</enabled>
      </releases>
      <snapshots>
        <enabled>true</enabled>
      </snapshots>
    </repository>
    <repository>
      <id>redhat</id>
      <url>https://maven.repository.redhat.com/ga/</url>
      <releases>
        <enabled>true</enabled>
      </releases>
      <snapshots>
        <enabled>true</enabled>
      </snapshots>
    </repository>
  </repositories>
  <pluginRepositories>
    <pluginRepository>
      <id>central</id>
      <url>https://repo.maven.apache.org/maven2/</url>
      <releases>
        <enabled>true</enabled>
      </releases>
      <snapshots>
        <enabled>true</enabled>
      </snapshots>
    </pluginRepository>
    <pluginRepository>
      <id>redhat</id>
      <url>https://maven.repository.redhat.com/ga/</url>
      <releases>
        <enabled>true</enabled>
      </releases>
      <snapshots>
        <enabled>true</enabled>
      </snapshots>
    </pluginRepository>
  </pluginRepositories>
```

Ajout d'un fichier **.mvn/maven.config** :

```
--settings=.mvn/local-settings.xml
```

Ajout d'un fichier **.mvn/local-settings.xml** :

```xml
<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.2.0 http://maven.apache.org/xsd/settings-1.2.0.xsd">
    <mirrors>
        <mirror>
            <id>mirror-central</id>
            <mirrorOf>central</mirrorOf>
            <name></name>
            <url>http://nxrm-ha-maven-repository.nexus.svc.cluster.local/repository/central</url>
        </mirror>
        <mirror>
            <id>mirror-redhat</id>
            <mirrorOf>redhat</mirrorOf>
            <name></name>
            <url>http://nxrm-ha-maven-repository.nexus.svc.cluster.local/repository/redhat</url>
        </mirror>
        <mirror>
            <id>maven-default-http-blocker</id>
            <mirrorOf>dummy</mirrorOf>
            <name>Dummy mirror to override default blocking mirror that blocks http</name>
            <url>http://0.0.0.0/</url>
            <blocked>false</blocked>
        </mirror>
    </mirrors>
</settings>
```

-> [How to disable maven blocking external HTTP repositories?](https://stackoverflow.com/questions/67001968/how-to-disable-maven-blocking-external-http-repositories)

### Auto Start / Auto Stop

Module commun (instancié une fois) :

```terraform
resource "aws_iam_policy" "scheduled_start_stop" {
  name   = "Scheduled-Start-Stop"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect   = "Allow"
        Action   = [
          "ec2:DescribeInstances",
          "ec2:StopInstances",
          "ec2:StartInstances"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role" "lambda_execution" {
  name = "Scheduled-Start-Stop"

  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}
```

Module à instancier par région :

```terraform
variable "region" {
  default = "eu-west-3"
}

provider "aws" {
  region = var.region
}

data "aws_iam_policy" "scheduled_start_stop" {
  name   = "Scheduled-Start-Stop"
}

data "aws_iam_role" "lambda_execution" {
  name = "Scheduled-Start-Stop"
}

resource "aws_iam_role_policy_attachment" "lambda_attach" {
  role       = data.aws_iam_role.lambda_execution.name
  policy_arn = data.aws_iam_policy.scheduled_start_stop.arn
}

data "archive_file" "stop_ec2_instances_zip" {
  type        = "zip"
  output_path = "${path.module}/stop.zip"
  source_content_filename = "lambda_function.py"
  source_content = <<-EOF
import boto3

region = '${var.region}'
ec2 = boto3.client('ec2', region_name=region)

def lambda_handler(event, context):
    filters = [
        {'Name': 'instance-state-name', 'Values': ['running']}
    ]
    response = ec2.describe_instances(Filters=filters)
    instances = [instance['InstanceId'] for reservation in response['Reservations'] for instance in reservation['Instances']]
    if instances:
        ec2.stop_instances(InstanceIds=instances)
        print('Stopped your instances: ' + str(instances))
    else:
        print('No instances found matching the criteria.')
  EOF
}

data "archive_file" "start_ec2_instances_zip" {
  type        = "zip"
  output_path = "${path.module}/start.zip"
  source_content_filename = "lambda_function.py"
  source_content = <<-EOF
import boto3

region = '${var.region}'
ec2 = boto3.client('ec2', region_name=region)

def lambda_handler(event, context):
    filters = [
        {'Name': 'instance-state-name', 'Values': ['stopped']}
    ]
    response = ec2.describe_instances(Filters=filters)
    instances = [instance['InstanceId'] for reservation in response['Reservations'] for instance in reservation['Instances']]
    if instances:
        ec2.start_instances(InstanceIds=instances)
        print('Started your instances: ' + str(instances))
    else:
        print('No instances found matching the criteria.')
  EOF
}

resource "aws_lambda_function" "stop_ec2_instances" {
  function_name    = "StopEC2Instances"
  handler          = "lambda_function.lambda_handler"
  role             = data.aws_iam_role.lambda_execution.arn
  runtime          = "python3.8"
  timeout          = 10
  filename         = data.archive_file.stop_ec2_instances_zip.output_path
  source_code_hash = data.archive_file.stop_ec2_instances_zip.output_base64sha256
}

resource "aws_lambda_function" "start_ec2_instances" {
  function_name    = "StartEC2Instances"
  handler          = "lambda_function.lambda_handler"
  role             = data.aws_iam_role.lambda_execution.arn
  runtime          = "python3.8"
  timeout          = 10
  filename         = data.archive_file.start_ec2_instances_zip.output_path
  source_code_hash = data.archive_file.start_ec2_instances_zip.output_base64sha256
}

resource "aws_cloudwatch_event_rule" "stop_ec2_instances_schedule" {
  name                = "StopEC2Instances"
  schedule_expression = "cron(30 17 * * ? *)" // UTC

}

resource "aws_cloudwatch_event_target" "stop_ec2_instances_target" {
  rule      = aws_cloudwatch_event_rule.stop_ec2_instances_schedule.name
  arn       = aws_lambda_function.stop_ec2_instances.arn
}

resource "aws_cloudwatch_event_rule" "start_ec2_instances_schedule" {
  name                = "StartEC2Instances"
  schedule_expression = "cron(30 7 ? * MON,TUE,WED,THU,FRI *)" // UTC
}

resource "aws_cloudwatch_event_target" "start_ec2_instances_target" {
  rule      = aws_cloudwatch_event_rule.start_ec2_instances_schedule.name
  arn       = aws_lambda_function.start_ec2_instances.arn
}

resource "aws_lambda_permission" "stop_ec2_instances_invoke" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.stop_ec2_instances.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.stop_ec2_instances_schedule.arn
}

resource "aws_lambda_permission" "start_ec2_instances_invoke" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.start_ec2_instances.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.start_ec2_instances_schedule.arn
}
```

Déploiement.

```sh
terraform init
terraform apply
```

Je note que les heure des crontab sont à ajuster suivant l'heure d'été / heure d'hiver.

- Heure d'été : 6:30 / 16:30
- Heure d'hiver: 7:30 / 17:30


### Déployer la démo

**CI/CD pipelines**

Créer le namespace `ci-pipelines` et provisioner le secret permettant de s'authentifier à quay.io.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  labels:
    kubernetes.io/metadata.name: ci-pipelines
  name: ci-pipelines
spec:
  finalizers:
  - kubernetes
---
apiVersion: v1
kind: Secret
metadata:
  name: quay-authentication
  namespace: ci-pipelines
data:
  .dockerconfigjson: REDACTED
type: kubernetes.io/dockerconfigjson
---
apiVersion: v1
kind: Secret
metadata:
  name: github-webhook-secret
  namespace: ci-pipelines
type: Opaque
stringData:
  secretToken: REDACTED
```

**GitOps**

Get the Webhook URL of your OpenShift Gitops installation

```shell
oc get route -n openshift-gitops openshift-gitops-server -o jsonpath='https://{.spec.host}/api/webhook'
```

Ajouter ce webhook sur le repo [gitops](https://github.com/Demo-AI-Edge-Crazy-Train/gitops).

Create the ArgoCD main application [as described](https://github.com/Demo-AI-Edge-Crazy-Train/gitops) :

```sh
oc apply -f argocd.yaml
```

Get the Webhook URL of the Tekton event listener

```sh
oc get route -n ci-pipelines el-crazy-train -o jsonpath='https://{.spec.host}/'
```

Ajouter le webhook sur les repos :

- [Demo-AI-Edge-Crazy-Train/train-controller](https://github.com/Demo-AI-Edge-Crazy-Train/train-controller)
- [Demo-AI-Edge-Crazy-Train/intelligent-train](https://github.com/Demo-AI-Edge-Crazy-Train/intelligent-train)
- [Demo-AI-Edge-Crazy-Train/train-ceq-app](https://github.com/Demo-AI-Edge-Crazy-Train/train-ceq-app)
- [Demo-AI-Edge-Crazy-Train/train-monitoring-app](https://github.com/Demo-AI-Edge-Crazy-Train/train-monitoring-app)
- [Demo-AI-Edge-Crazy-Train/train-capture-image-app](https://github.com/Demo-AI-Edge-Crazy-Train/train-capture-image-app)

Webhook parameters :

- **Content-Type**: `application/json`
- **SSL verification**: `disabled`
- **Shared Secret**: `REDACTED`

## Reconfiguration du train

**Mettre à jour la configuration du train**

Récupérer l'adresse du Load Balancer du Kafka

```sh
oc get svc operating-center-kafka-external-bootstrap -n operating-center -o jsonpath='{.status.loadBalancer.ingress[0].hostname}:9094'
```

Mettre à jour la ConfigMap :

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ceq-app-env
  namespace: train
data:
  BROKER_KAFKA_URL: tcp://a39b5659358b942dcad175676d1d2765-1769354420.eu-west-3.elb.amazonaws.com:9094
  BROKER_MQTT_URL: tcp://mosquitto:1883
  CAMEL_COMPONENT_KAFKA_SASL_JAAS_CONFIG: org.apache.kafka.common.security.scram.ScramLoginModule
    required username='train' password='R3dH4t1!';
  CAMEL_COMPONENT_KAFKA_SASL_MECHANISM: SCRAM-SHA-512
  CAMEL_COMPONENT_KAFKA_SECURITY_PROTOCOL: SASL_PLAINTEXT
  KAFKA_BOOTSTRAP_SERVERS: a39b5659358b942dcad175676d1d2765-1769354420.eu-west-3.elb.amazonaws.com:9094
  KAFKA_TOPIC_CAPTURE_NAME: train-command-capture
  KAFKA_TOPIC_NAME: train-monitoring
  LOGGER_LEVEL: INFO
  LOGGER_LEVEL_CATEGORY_CAMEL: INFO
  MQTT_DEST_TOPIC_NAME: train-command
  MQTT_SRC_TOPIC_NAME: train-model-result
  TRAIN_HTTP_URL: http://capture-app:8080/capture
```

Redémarrer le pod "ceq-app".

```sh
oc -n train delete pod -l app=ceq-app
```

Sur le train, démarrer la démo :

```sh
sudo -i
export KUBECONFIG=/var/lib/microshift/resources/kubeadmin/kubeconfig
oc -n train rsh deploy/capture-app curl -v -XPOST http://capture-app:8080/capture/start
```

Récupérer l'URL de l'application monitoring et s'y connecter :

```shell
oc get route -n operating-center monitoring-app -o jsonpath='https://{.spec.host}/'
```

Appuyer sur le bouton du Hub Lego et attendre que le Pod train-controller s'y connecte.

S'il a du mal à s'y connecter, le supprimer.

```sh
oc -n train delete pod -l app=train-controller
```

## Déployer le Lab

Je reprends ce qu'on avait fait pour le Riviera Dev mais je n'ai pas beaucoup de notes.

Je commence par forker les deux repos (lab statement + monorepo code).

- [open-tour-2024-lab-statement](https://github.com/Demo-AI-Edge-Crazy-Train/open-tour-2024-lab-statement)
- [opentour2024-app](https://github.com/Demo-AI-Edge-Crazy-Train/opentour2024-app)
- [opentour2024-gitops](https://github.com/Demo-AI-Edge-Crazy-Train/opentour2024-gitops)

Et je déclare le nouveau site dans netlify.

**Installer DevSpaces**

```yaml
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: devspaces
  namespace: openshift-operators
spec:
  channel: stable
  name: devspaces
  source: redhat-operators
  sourceNamespace: openshift-marketplace
---
apiVersion: v1
kind: Namespace
metadata:
  labels:
    kubernetes.io/metadata.name: openshift-devspaces
  name: openshift-devspaces
spec:
  finalizers:
  - kubernetes
---
apiVersion: org.eclipse.che/v2
kind: CheCluster
metadata:
  name: devspaces
  namespace: openshift-devspaces
spec:
  components:
    cheServer:
      debug: false
      logLevel: INFO
    metrics:
      enable: true
    pluginRegistry: {}
  containerRegistry: {}
  devEnvironments:
    startTimeoutSeconds: 300
    secondsOfRunBeforeIdling: -1
    maxNumberOfWorkspacesPerUser: -1
    containerBuildConfiguration:
      openShiftSecurityContextConstraint: container-build
    defaultNamespace:
      autoProvision: true
      template: <username>-devspaces
    secondsOfInactivityBeforeIdling: 1800
    storage: {}
  gitServices: {}
  networking: {}
```

Récupérer l'URL de la callback OAuth de Dev Spaces :

```
$ oc get checluster devspaces -n openshift-devspaces -o go-template='{{.status.cheURL}}/api/oauth/callback'

https://devspaces.apps.crazy-train.sandbox1730.opentlc.com/api/oauth/callback
```

Et créer une application OAuth [dans l'orga GitHub](https://github.com/organizations/Demo-AI-Edge-Crazy-Train/settings/applications/new).

- **Application name**: `OpenShift Dev Spaces`
- **Homepage URL**: *libre choix*
- **Authorization callback URL**: *le résultat de la commande ci-dessus*

![OpenShift DevSpaces - GitHub OAuth Application](./2024-11%20OpenShift%20DevSpaces%20-%20GitHub%20OAuth%20Application.png)

Créer le secret correspondant :

```yaml
kind: Secret
apiVersion: v1
metadata:
  name: github-oauth-config
  namespace: openshift-devspaces
  labels:
    app.kubernetes.io/part-of: che.eclipse.org
    app.kubernetes.io/component: oauth-scm-configuration
  annotations:
    che.eclipse.org/oauth-scm-server: github
    che.eclipse.org/scm-server-endpoint: https://github.com
type: Opaque
stringData:
  id: REDACTED
  secret: REDACTED
```

Éditer le badge du [README.md](https://github.com/Demo-AI-Edge-Crazy-Train/opentour2024-app/edit/main/README.md) :

```markdown
[![Contribute](https://www.eclipse.org/che/contribute.svg)](https://devspaces.apps.crazy-train.sandbox1730.opentlc.com/f?url=https://github.com/Demo-AI-Edge-Crazy-Train/opentour2024-app)
```

**Déployer les utilisateurs**

Créer les namespaces et le htpasswd.

```sh
git clone git@github.com:Demo-AI-Edge-Crazy-Train/opentour2024-gitops.git
cd opentour2024-gitops/authentication
helm template auth . --set masterKey=0p3nT0ur2024 | oc apply -f -
SECRET_NAME="$(oc get secret -n openshift-config --sort-by='{.metadata.creationTimestamp}' -o name | sed -r 's|^secret/(htpasswd-.*)$|\1|;t;d')"
echo $SECRET_NAME
```

Mettre à jour l'IdP OAuth.

```sh
oc edit oauth.config.openshift.io cluster
```

```yaml
apiVersion: config.openshift.io/v1
kind: OAuth
metadata:
  name: cluster
  annotations:
    argocd.argoproj.io/sync-options: Prune=false
spec:
  identityProviders:
  - htpasswd:
      fileData:
        name: htpasswd-2e3ee03b
    mappingMethod: claim
    name: WorkshopUser
    type: HTPasswd
```

Exporter les mots de passe.

```sh
oc extract secret/$SECRET_NAME --to=- -n openshift-config --keys=users.txt 2>/dev/null > ../labels/users/users.csv
```

**Déployer l'image UDI**

Copier l'image `universal-developer-image:opencv` dans la registry interne OpenShift.

```sh
# Expose the registry to the outside world
oc patch configs.imageregistry.operator.openshift.io/cluster --type=merge -p '{"spec":{"defaultRoute": true}}'

# Prepare URL and credentials
OPENSHIFT_REGISTRY=$(oc get -n openshift-image-registry route/default-route -o 'jsonpath={.spec.host}{"\n"}')
TOKEN="$(oc create token builder -n openshift --duration=$((365*24))h)"

# Copy the image
skopeo copy docker://quay.io/demo-ai-edge-crazy-train/universal-developer-image:opencv docker://$OPENSHIFT_REGISTRY/openshift/universal-developer-image:opencv --dest-registry-token="$TOKEN"
```

**Déployer et configurer OpenShift AI**

-> https://github.com/Demo-AI-Edge-Crazy-Train/ai-workshop

**Mettre à jour le devfile**

Dans le devfile, faire les modifications suivantes.

```yaml
schemaVersion: 2.2.2
metadata:
  name: demo-ai-edge-crazy-train
  description: "Demo AI Edge Crazy Train"
components:
  - name: tools
    container:
      image: "image-registry.openshift-image-registry.svc:5000/openshift/universal-developer-image:opencv"
      args: ['tail', '-f', '/dev/null']
      env:
        - name: CHE_DASHBOARD_URL
          value: 'https://devspaces.apps.crazy-train.sandbox1730.opentlc.com/dashboard'
        - name: CHE_PLUGIN_REGISTRY_URL
          value: 'https://devspaces.apps.crazy-train.sandbox1730.opentlc.com/plugin-registry/v3'
```

Au démarrage du workspace, j'ai une erreur dans les logs du container **tools**.

```
Kubedock is disabled. It can be enabled with the env variable "KUBEDOCK_ENABLED=true"
set in the workspace Devfile or in a Kubernetes ConfigMap in the developer namespace.
```

Dans les logs du node, j'ai :

```
Nov 19 16:56:43 ip-10-0-56-158 kubenswrapper[2343]: E1119 16:56:43.340526    2343 pod_workers.go:1298] "Error syncing pod, skipping" err="failed to \"StartContainer\" for \"tools\" with PostStartHookError: \"Exec lifecycle hook ([/bin/sh -c {\\nnohup /checode/entrypoint-volume.sh > /checode/entrypoint-logs.txt 2>&1 &\\ncd /\\nmkdir -p ~/maven \\\\\\n&& curl -fsSL https://archive.apache.org/dist/maven/maven-3/3.8.2/binaries/apache-maven-3.8.2-bin.tar.gz | tar -xzC ~/maven  > /tmp/install-maven.log 2>&1 \\\\\\n&& echo 'export PATH=/home/user/maven/apache-maven-3.8.2/bin:$PATH' >> ~/.bashrc\\n\\ncd /\\ncd /projects/rivieradev-app/train-controller && npm install \\n\\ncd /\\ncd /projects/rivieradev-app/intelligent-train &&  pip install -r src/requirements.txt \\n\\n} 1>/tmp/poststart-stdout.txt 2>/tmp/poststart-stderr.txt\\n]) for Container \\\"tools\\\" in Pod \\\"workspace8ee1df08e7cc4d19-58c9d95c94-x46tq_user39-devspaces(d117c870-b913-42a0-a0b6-071d31db35b9)\\\" failed - error: command '/bin/sh -c {\\nnohup /checode/entrypoint-volume.sh > /checode/entrypoint-logs.txt 2>&1 &\\ncd /\\nmkdir -p ~/maven \\\\\\n&& curl -fsSL https://archive.apache.org/dist/maven/maven-3/3.8.2/binaries/apache-maven-3.8.2-bin.tar.gz | tar -xzC ~/maven  > /tmp/install-maven.log 2>&1 \\\\\\n&& echo 'export PATH=/home/user/maven/apache-maven-3.8.2/bin:$PATH' >> ~/.bashrc\\n\\ncd /\\ncd /projects/rivieradev-app/train-controller && npm install \\n\\ncd /\\ncd /projects/rivieradev-app/intelligent-train &&  pip install -r src/requirements.txt \\n\\n} 1>/tmp/poststart-stdout.txt 2>/tmp/poststart-stderr.txt\\n' exited with 1: , message: \\\"\\\"\"" pod="user39-devspaces/workspace8ee1df08e7cc4d19-58c9d95c94-x46tq" podUID="d117c870-b913-42a0-a0b6-071d31db35b9"
```

-> C'est une typo dans les chemins d'accès au projet.

```diff
diff --git a/devfile.yaml b/devfile.yaml
index 711dc96..5715aaa 100644
--- a/devfile.yaml
+++ b/devfile.yaml
@@ -126,14 +126,14 @@ commands:
   - id: install-python-requirements
     exec:
       commandLine: |
-        cd /projects/rivieradev-app/intelligent-train &&  pip install -r src/requirements.txt
+        cd /projects/opentour2024-app/intelligent-train &&  pip install -r src/requirements.txt
       component: tools
       env: []
       workingDir: "/"
   - id: install-node-requirements
     exec:
       commandLine: |
-       cd /projects/rivieradev-app/train-controller && npm install
+       cd /projects/opentour2024-app/train-controller && npm install
       component: tools
       env: []
       workingDir: "/"
```

J'ai remis à jour les repo opentour2024-app et open-tour-2024-lab-statement pour changer :

- les URLs des clusters
- les URLs des Git
- les chemins d'accès
