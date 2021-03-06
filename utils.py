paths = [
    "/.well-known/openid-configuration",
    "/api",
    "/api/v1",
    "/apis",
    "/apis/",
    "/apis/admissionregistration.k8s.io",
    "/apis/admissionregistration.k8s.io/v1",
    "/apis/admissionregistration.k8s.io/v1beta1",
    "/apis/apiextensions.k8s.io",
    "/apis/apiextensions.k8s.io/v1",
    "/apis/apiextensions.k8s.io/v1beta1",
    "/apis/apiregistration.k8s.io",
    "/apis/apiregistration.k8s.io/v1",
    "/apis/apiregistration.k8s.io/v1beta1",
    "/apis/apps",
    "/apis/apps.openshift.io",
    "/apis/apps.openshift.io/v1",
    "/apis/apps/v1",
    "/apis/authentication.k8s.io",
    "/apis/authentication.k8s.io/v1",
    "/apis/authentication.k8s.io/v1beta1",
    "/apis/authentication.maistra.io",
    "/apis/authentication.maistra.io/v1",
    "/apis/authorization.k8s.io",
    "/apis/authorization.k8s.io/v1",
    "/apis/authorization.k8s.io/v1beta1",
    "/apis/authorization.openshift.io",
    "/apis/authorization.openshift.io/v1",
    "/apis/authorization.openshift.io/v1/rolebindingrestrictions",
    "/apis/autoscaling",
    "/apis/autoscaling.openshift.io",
    "/apis/autoscaling.openshift.io/v1",
    "/apis/autoscaling.openshift.io/v1beta1",
    "/apis/autoscaling/v1",
    "/apis/autoscaling/v2beta1",
    "/apis/autoscaling/v2beta2",
    "/apis/batch",
    "/apis/batch/v1",
    "/apis/batch/v1beta1",
    "/apis/build.openshift.io",
    "/apis/build.openshift.io/v1",
    "/apis/certificates.k8s.io",
    "/apis/certificates.k8s.io/v1",
    "/apis/certificates.k8s.io/v1beta1",
    "/apis/cloudcredential.openshift.io",
    "/apis/cloudcredential.openshift.io/v1",
    "/apis/config.istio.io",
    "/apis/config.istio.io/v1alpha2",
    "/apis/config.openshift.io",
    "/apis/config.openshift.io/v1",
    "/apis/console.openshift.io",
    "/apis/console.openshift.io/v1",
    "/apis/console.openshift.io/v1alpha1",
    "/apis/controlplane.operator.openshift.io",
    "/apis/controlplane.operator.openshift.io/v1alpha1",
    "/apis/coordination.k8s.io",
    "/apis/coordination.k8s.io/v1",
    "/apis/coordination.k8s.io/v1beta1",
    "/apis/discovery.k8s.io",
    "/apis/discovery.k8s.io/v1beta1",
    "/apis/events.k8s.io",
    "/apis/events.k8s.io/v1",
    "/apis/events.k8s.io/v1beta1",
    "/apis/extensions",
    "/apis/extensions/v1beta1",
    "/apis/flowcontrol.apiserver.k8s.io",
    "/apis/flowcontrol.apiserver.k8s.io/v1alpha1",
    "/apis/flowcontrol.apiserver.k8s.io/v1beta1",
    "/apis/helm.openshift.io",
    "/apis/helm.openshift.io/v1beta1",
    "/apis/image.openshift.io",
    "/apis/image.openshift.io/v1",
    "/apis/imageregistry.operator.openshift.io",
    "/apis/imageregistry.operator.openshift.io/v1",
    "/apis/ingress.operator.openshift.io",
    "/apis/ingress.operator.openshift.io/v1",
    "/apis/jaegertracing.io",
    "/apis/jaegertracing.io/v1",
    "/apis/k8s.cni.cncf.io",
    "/apis/k8s.cni.cncf.io/v1",
    "/apis/kiali.io",
    "/apis/kiali.io/v1alpha1",
    "/apis/logging.openshift.io",
    "/apis/logging.openshift.io/v1",
    "/apis/machine.openshift.io",
    "/apis/machine.openshift.io/v1beta1",
    "/apis/machineconfiguration.openshift.io",
    "/apis/machineconfiguration.openshift.io/v1",
    "/apis/maistra.io",
    "/apis/maistra.io/v1",
    "/apis/maistra.io/v1alpha1",
    "/apis/maistra.io/v2",
    "/apis/metal3.io",
    "/apis/metal3.io/v1alpha1",
    "/apis/metrics.k8s.io",
    "/apis/metrics.k8s.io/v1beta1",
    "/apis/migration.k8s.io",
    "/apis/migration.k8s.io/v1alpha1",
    "/apis/monitoring.coreos.com",
    "/apis/monitoring.coreos.com/v1",
    "/apis/monitoring.coreos.com/v1alpha1",
    "/apis/monitoring.kiali.io",
    "/apis/monitoring.kiali.io/v1alpha1",
    "/apis/network.openshift.io",
    "/apis/network.openshift.io/v1",
    "/apis/network.operator.openshift.io",
    "/apis/network.operator.openshift.io/v1",
    "/apis/networking.istio.io",
    "/apis/networking.istio.io/v1alpha3",
    "/apis/networking.istio.io/v1beta1",
    "/apis/networking.k8s.io",
    "/apis/networking.k8s.io/v1",
    "/apis/networking.k8s.io/v1beta1",
    "/apis/node.k8s.io",
    "/apis/node.k8s.io/v1",
    "/apis/node.k8s.io/v1beta1",
    "/apis/oauth.openshift.io",
    "/apis/oauth.openshift.io/v1",
    "/apis/operator.openshift.io",
    "/apis/operator.openshift.io/v1",
    "/apis/operator.openshift.io/v1alpha1",
    "/apis/operators.coreos.com",
    "/apis/operators.coreos.com/v1",
    "/apis/operators.coreos.com/v1alpha1",
    "/apis/operators.coreos.com/v1alpha2",
    "/apis/packages.operators.coreos.com",
    "/apis/packages.operators.coreos.com/v1",
    "/apis/policy",
    "/apis/policy/v1beta1",
    "/apis/project.openshift.io",
    "/apis/project.openshift.io/v1",
    "/apis/quota.openshift.io",
    "/apis/quota.openshift.io/v1",
    "/apis/quota.openshift.io/v1/clusterresourcequotas",
    "/apis/rbac.authorization.k8s.io",
    "/apis/rbac.authorization.k8s.io/v1",
    "/apis/rbac.authorization.k8s.io/v1beta1",
    "/apis/rbac.istio.io",
    "/apis/rbac.istio.io/v1alpha1",
    "/apis/rbac.maistra.io",
    "/apis/rbac.maistra.io/v1",
    "/apis/route.openshift.io",
    "/apis/route.openshift.io/v1",
    "/apis/samples.operator.openshift.io",
    "/apis/samples.operator.openshift.io/v1",
    "/apis/scheduling.k8s.io",
    "/apis/scheduling.k8s.io/v1",
    "/apis/scheduling.k8s.io/v1beta1",
    "/apis/security.internal.openshift.io",
    "/apis/security.internal.openshift.io/v1",
    "/apis/security.istio.io",
    "/apis/security.istio.io/v1beta1",
    "/apis/security.openshift.io",
    "/apis/security.openshift.io/v1",
    "/apis/security.openshift.io/v1/securitycontextconstraints",
    "/apis/snapshot.storage.k8s.io",
    "/apis/snapshot.storage.k8s.io/v1",
    "/apis/snapshot.storage.k8s.io/v1beta1",
    "/apis/storage.k8s.io",
    "/apis/storage.k8s.io/v1",
    "/apis/storage.k8s.io/v1beta1",
    "/apis/template.openshift.io",
    "/apis/template.openshift.io/v1",
    "/apis/tuned.openshift.io",
    "/apis/tuned.openshift.io/v1",
    "/apis/user.openshift.io",
    "/apis/user.openshift.io/v1",
    "/apis/whereabouts.cni.cncf.io",
    "/apis/whereabouts.cni.cncf.io/v1alpha1",
    "/healthz",
    "/healthz/autoregister-completion",
    "/healthz/etcd",
    "/healthz/log",
    "/healthz/ping",
    "/healthz/poststarthook/aggregator-reload-proxy-client-cert",
    "/healthz/poststarthook/apiservice-openapi-controller",
    "/healthz/poststarthook/apiservice-registration-controller",
    "/healthz/poststarthook/apiservice-status-available-controller",
    "/healthz/poststarthook/apiservice-wait-for-first-sync",
    "/healthz/poststarthook/bootstrap-controller",
    "/healthz/poststarthook/crd-informer-synced",
    "/healthz/poststarthook/generic-apiserver-start-informers",
    "/healthz/poststarthook/kube-apiserver-autoregistration",
    "/healthz/poststarthook/openshift.io-StartOAuthInformers",
    "/healthz/poststarthook/openshift.io-TokenTimeoutUpdater",
    "/healthz/poststarthook/openshift.io-oauth-apiserver-reachable",
    "/healthz/poststarthook/openshift.io-openshift-apiserver-reachable",
    "/healthz/poststarthook/openshift.io-startkubeinformers",
    "/healthz/poststarthook/priority-and-fairness-config-consumer",
    "/healthz/poststarthook/priority-and-fairness-config-producer",
    "/healthz/poststarthook/priority-and-fairness-filter",
    "/healthz/poststarthook/quota.openshift.io-clusterquotamapping",
    "/healthz/poststarthook/rbac/bootstrap-roles",
    "/healthz/poststarthook/scheduling/bootstrap-system-priority-classes",
    "/healthz/poststarthook/start-apiextensions-controllers",
    "/healthz/poststarthook/start-apiextensions-informers",
    "/healthz/poststarthook/start-cluster-authentication-info-controller",
    "/healthz/poststarthook/start-kube-aggregator-informers",
    "/healthz/poststarthook/start-kube-apiserver-admission-initializer",
    "/livez",
    "/livez/autoregister-completion",
    "/livez/etcd",
    "/livez/log",
    "/livez/ping",
    "/livez/poststarthook/aggregator-reload-proxy-client-cert",
    "/livez/poststarthook/apiservice-openapi-controller",
    "/livez/poststarthook/apiservice-registration-controller",
    "/livez/poststarthook/apiservice-status-available-controller",
    "/livez/poststarthook/apiservice-wait-for-first-sync",
    "/livez/poststarthook/bootstrap-controller",
    "/livez/poststarthook/crd-informer-synced",
    "/livez/poststarthook/generic-apiserver-start-informers",
    "/livez/poststarthook/kube-apiserver-autoregistration",
    "/livez/poststarthook/openshift.io-StartOAuthInformers",
    "/livez/poststarthook/openshift.io-TokenTimeoutUpdater",
    "/livez/poststarthook/openshift.io-oauth-apiserver-reachable",
    "/livez/poststarthook/openshift.io-openshift-apiserver-reachable",
    "/livez/poststarthook/openshift.io-startkubeinformers",
    "/livez/poststarthook/priority-and-fairness-config-consumer",
    "/livez/poststarthook/priority-and-fairness-config-producer",
    "/livez/poststarthook/priority-and-fairness-filter",
    "/livez/poststarthook/quota.openshift.io-clusterquotamapping",
    "/livez/poststarthook/rbac/bootstrap-roles",
    "/livez/poststarthook/scheduling/bootstrap-system-priority-classes",
    "/livez/poststarthook/start-apiextensions-controllers",
    "/livez/poststarthook/start-apiextensions-informers",
    "/livez/poststarthook/start-cluster-authentication-info-controller",
    "/livez/poststarthook/start-kube-aggregator-informers",
    "/livez/poststarthook/start-kube-apiserver-admission-initializer",
    "/metrics",
    "/openapi/v2",
    "/openid/v1/jwks",
    "/readyz",
    "/readyz/api-openshift-apiserver-available",
    "/readyz/api-openshift-oauth-apiserver-available",
    "/readyz/autoregister-completion",
    "/readyz/etcd",
    "/readyz/informer-sync",
    "/readyz/log",
    "/readyz/ping",
    "/readyz/poststarthook/aggregator-reload-proxy-client-cert",
    "/readyz/poststarthook/apiservice-openapi-controller",
    "/readyz/poststarthook/apiservice-registration-controller",
    "/readyz/poststarthook/apiservice-status-available-controller",
    "/readyz/poststarthook/apiservice-wait-for-first-sync",
    "/readyz/poststarthook/bootstrap-controller",
    "/readyz/poststarthook/crd-informer-synced",
    "/readyz/poststarthook/generic-apiserver-start-informers",
    "/readyz/poststarthook/kube-apiserver-autoregistration",
    "/readyz/poststarthook/openshift.io-StartOAuthInformers",
    "/readyz/poststarthook/openshift.io-TokenTimeoutUpdater",
    "/readyz/poststarthook/openshift.io-oauth-apiserver-reachable",
    "/readyz/poststarthook/openshift.io-openshift-apiserver-reachable",
    "/readyz/poststarthook/openshift.io-startkubeinformers",
    "/readyz/poststarthook/priority-and-fairness-config-consumer",
    "/readyz/poststarthook/priority-and-fairness-config-producer",
    "/readyz/poststarthook/priority-and-fairness-filter",
    "/readyz/poststarthook/quota.openshift.io-clusterquotamapping",
    "/readyz/poststarthook/rbac/bootstrap-roles",
    "/readyz/poststarthook/scheduling/bootstrap-system-priority-classes",
    "/readyz/poststarthook/start-apiextensions-controllers",
    "/readyz/poststarthook/start-apiextensions-informers",
    "/readyz/poststarthook/start-cluster-authentication-info-controller",
    "/readyz/poststarthook/start-kube-aggregator-informers",
    "/readyz/poststarthook/start-kube-apiserver-admission-initializer",
    "/readyz/shutdown",
    "/version"
]

usage = """"./runtool.py [-h] [--token [TOKEN]] -targets [TARGETS] [--paths [PATHS]] [--resolve [BOOL]]"""
__author__ = "@rive_n or https://t.me/r1v3ns_life"

logo = r"""

 ??????????????????   ?????????     ??????????????????   ???    ?????? ?????????????????????  ????????? ????????????    ??? ?????????????????????????????????????????????  ?????????     ?????????     ?????????  ??????????????? ??????????????????  ????????????    ???  ??????????????????  ?????????????????? 
???????????? ??????  ????????????    ????????????  ????????? ??????  ???????????????????????? ????????????????????? ?????? ??????   ??? ???  ????????? ????????????   ??? ????????????    ????????????    ???????????? ????????? ???????????????   ???  ?????? ??????   ??? ???????????? ??????  ??????   ??? 
?????????    ??? ????????????    ????????????  ??????????????????  ?????????????????????   ???????????????????????????  ?????? ???????????? ???????????? ??????????????????   ????????????    ????????????    ????????????????????????????????????????????????   ?????????  ?????? ??????????????????    ??? ????????????   
???????????? ????????????????????????    ?????????   ??????????????????  ????????????????????????   ???????????????????????????  ?????????????????? ???????????? ??? ?????????  ??? ????????????    ????????????    ?????????????????????  ??????????????????  ??? ????????????  ??????????????????????????? ?????????????????????  ??? 
??? ??????????????? ?????????????????????????????? ????????????????????????????????????????????? ????????????????????? ????????????????????????   ????????????  ???????????? ??? ??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????   ??????????????? ??????????????? ????????????????????????
??? ?????? ???  ?????? ?????????  ?????? ?????????????????? ???????????? ??? ???  ?????????  ??? ??????  ??? ??????   ??? ???   ??? ??????   ?????? ?????? ?????? ?????????  ?????? ?????????  ?????????   ??????   ??? ?????? ?????? ?????? ??????   ??? ??? ??? ?????? ???  ????????? ?????? ???
  ???  ???   ??? ??? ???  ???  ??? ??? ?????? ???????????? ??? ???  ??? ???  ???  ??? ?????? ??????   ??? ??????    ???     ??? ???  ?????? ??? ???  ?????? ??? ???  ??? ??? ???  ???   ???  ??? ???  ?????? ??????   ??? ??????  ???  ???    ??? ???  ???
???          ??? ???   ??? ??? ??? ???   ????????? ??? ???  ??? ???  ???  ??? ???   ???   ??? ???   ???         ???     ??? ???     ??? ???    ??? ?????? ???   ???    ???      ???   ??? ??? ???           ???   
??? ???          ???  ???    ??? ???     ???        ???     ???           ???             ???  ???    ???  ???    ???  ??? ???        ???    ???  ???         ??? ??? ???         ???  ???
???                                   ???                                                                                   ???                                                                                                                                                                                                                                             
""" + "Author: " + __author__

description = """Kubernetes, also known as K8s, is an open-source system for automating deployment, 
scaling, and management of containerized applications. It groups containers that make up an application into logical 
units for easy management and discovery. That's really big infrastructure so this tool is created for 
security checks. This tool is scanning: most vulnerable and open ports, walking through the RHOCP API.  
You don't need to care about methods like: ["shutdown", "drop", "stop", "delete"]. They are not CHECKED for 
some reasons. This tool also draws tables with results so you can nicely watch what is done with k8s infro.\n
"""

