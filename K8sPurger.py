#!/usr/bin/env python

import argparse
import os
import time

import urllib3
from kubernetes import config, client
from prometheus_client import start_http_server, Gauge

urllib3.disable_warnings()

USED_SECRET, USED_CONFIG_MAP, USED_PVC, USED_EP, USED_SA, EXTRA_INGRESS = (
    [],
    [],
    [],
    [],
    [],
    [],
)
INGRESS, ROLE_BINDING = {}, {}
GAUGE = Gauge(
    "k8s_unused_resources",
    "show unused resources in k8s",
    ["type", "name", "namespaces"],
)

EXCLUDE_NAMESPACES_LIST = ["kube-system", "kube-public"]
EXCLUDED_SECRET_TYPES = [
    "kubernetes.io/tls",
    "kubernetes.io/service-account-token",
    "kubernetes.io/dockercfg",
]


def main(svc, namespace=None):
    GAUGE.clear()
    try:
        if svc == "svc":
            config.load_incluster_config()
        else:
            config.load_kube_config()
        v1 = client.CoreV1Api()
        try:
            v1_ingress_api = client.ExtensionsV1beta1Api()
        except Exception:
            v1_ingress_api = client.NetworkingV1Api()
        rbac_authorization_v1_api = client.RbacAuthorizationV1Api()
        apps_v1_api = client.AppsV1Api()
    except Exception as err:
        print("Not able to read Kubernetes cluster check Kubeconfig")
        raise err
    print("Getting unused secret it may take couple of minute..")
    get_used_resources(v1, namespace=namespace)
    Secrets = defined_secret(v1, namespace=namespace)
    ExtraSecret = diff_lists(Secrets, USED_SECRET)
    print_list(ExtraSecret, "Secrets")
    print("Getting unused ConfigMap it may take couple of minute..")
    ConfigMap = defined_config_map(v1, namespace=namespace)
    ExtraConfigMap = diff_lists(ConfigMap, USED_CONFIG_MAP)
    print_list(ExtraConfigMap, "ConfigMap")
    print("Getting unused PVC it may take couple of minute..")
    PVC = defined_persistent_volume_claim(v1, namespace=namespace)
    ExtraPVC = diff_lists(PVC, USED_PVC)
    print_list(ExtraPVC, "PV Claim")
    print("Getting unused services it may take couple of minute..")
    UsedEP = get_used_services(v1, namespace=namespace)
    EP = defined_svc(v1, namespace=namespace)
    ExtraSVC = diff_lists(EP, UsedEP)
    print_list(ExtraSVC, "Services")
    print("Getting unused Ingress it may take couple of minute..")
    defined_ingress(v1_ingress_api, namespace=namespace)
    ExtraIng = get_unused_ingress(EP, ExtraSVC)
    print_list(ExtraIng, "Ingress")
    print("Getting unused service account it may take couple of minute..")
    SA = defined_service_account(v1, namespace=namespace)
    ExtraSA = diff_lists(SA, USED_SA)
    print_list(ExtraSA, "Service Account")
    print("Getting unused Roles Binding it may take couple of minute..")
    _ = defined_role_binding(rbac_authorization_v1_api, namespace=namespace)
    ExtraRB = get_unused_rb(SA, ExtraSA)
    print_list(ExtraRB, "Role Binding")
    ExtraDep = get_unused_deployment(apps_v1_api, namespace=namespace)
    print_list(ExtraDep, "Deployment")
    ExtraSTS = get_unused_sts(apps_v1_api, namespace=namespace)
    print_list(ExtraSTS, "Stateful Sets")

    if svc == "svc":
        refresh_interval = os.environ["REFRESH_INTERVAL"]
        time.sleep(int(refresh_interval))


def excluded_namespace(namespace):
    for ens in EXCLUDE_NAMESPACES_LIST:
        if ens in namespace:
            return True
    return False


def diff_lists(list_a, list_b):
    return [item for item in list_a if item not in list_b]


def print_list(list_to_print, name):
    if len(list_to_print) == 0:
        print("Hurray You don't have a unused " + name)
    else:
        print(
            "\nExtra "
            + name
            + " are "
            + str(len(list_to_print))
            + " which are as below\n"
        )
        size1 = max(len(word[0]) for word in list_to_print)
        size2 = max(len(word[1]) for word in list_to_print)
        borderchar = "|"
        linechar = "-"
        print(linechar * (size1 + size2 + 7))
        print(
            "{bc} {:<{}} {bc}".format(name, size1, bc=borderchar)
            + "{:<{}} {bc}".format("Namespace", size2, bc=borderchar)
        )
        print(linechar * (size1 + size2 + 7))
        for word in list_to_print:
            print(
                "{bc} {:<{}} {bc}".format(word[0], size1, bc=borderchar)
                + "{:<{}} {bc}".format(word[1], size2, bc=borderchar)
            )

            GAUGE.labels(name, word[0], word[1]).set(1)
        print(linechar * (size1 + size2 + 7))
    print(" ")


def get_used_resources(v1, namespace=None):
    try:
        if namespace is None:
            api_response = v1.list_pod_for_all_namespaces()
        else:
            api_response = v1.list_namespaced_pod(namespace=namespace)
    except Exception as err:
        print("Not able to reach Kubernetes cluster check Kubeconfig")
        raise err
    for pod in api_response.items:
        if excluded_namespace(pod.metadata.namespace):
            pass
        else:
            containers = pod.spec.containers
            for container in containers:
                if container.env is not None:
                    for env in container.env:
                        if env.value_from is not None:
                            if env.value_from.secret_key_ref is not None:
                                USED_SECRET.append(
                                    [
                                        env.value_from.secret_key_ref.name,
                                        pod.metadata.namespace,
                                    ]
                                )
                            elif env.value_from.config_map_key_ref is not None:
                                USED_CONFIG_MAP.append(
                                    [
                                        env.value_from.config_map_key_ref.name,
                                        pod.metadata.namespace,
                                    ]
                                )
                if container.env_from is not None:
                    for env_from in container.env_from:
                        if env_from.config_map_ref is not None:
                            USED_CONFIG_MAP.append(
                                [env_from.config_map_ref.name, pod.metadata.namespace]
                            )
                        elif env_from.secret_ref is not None:
                            USED_SECRET.append(
                                [env_from.secret_ref.name, pod.metadata.namespace]
                            )
            if pod.spec.volumes is not None:
                for volume in pod.spec.volumes:
                    if volume.secret is not None:
                        USED_SECRET.append(
                            [volume.secret.secret_name, pod.metadata.namespace]
                        )
                    elif volume.config_map is not None:
                        USED_CONFIG_MAP.append(
                            [volume.config_map.name, pod.metadata.namespace]
                        )
                    elif volume.persistent_volume_claim is not None:
                        USED_PVC.append(
                            [
                                volume.persistent_volume_claim.claim_name,
                                pod.metadata.namespace,
                            ]
                        )
            if pod.spec.service_account_name is not None:
                USED_SA.append([pod.spec.service_account_name, pod.metadata.namespace])


def defined_svc(v1, namespace=None):
    EP = []
    try:
        api_response = v1.list_namespaced_service(namespace=namespace)
    except Exception as err:
        print("Not able to reach Kubernetes cluster check Kubeconfig")
        raise err
    for i in api_response.items:
        if not excluded_namespace(i.metadata.namespace):
            EP.append([i.metadata.name, i.metadata.namespace])
    return EP


def get_used_services(v1, namespace=None):
    UsedEP = []
    try:
        api_response = v1.list_namespaced_endpoints(namespace=namespace)
    except Exception as err:
        print("Not able to reach Kubernetes cluster check Kubeconfig")
        raise err
    for i in api_response.items:
        if not excluded_namespace(i.metadata.namespace):
            UsedEP.append([i.metadata.name, i.metadata.namespace])
    return UsedEP


def defined_secret(v1, namespace=None):
    Secrets = []
    try:
        if namespace is None:
            api_response = v1.list_secret_for_all_namespaces()
        else:
            api_response = v1.list_namespaced_secret(namespace=namespace)
    except Exception as err:
        print("Not able to reach Kubernetes cluster check Kubeconfig")
        raise err
    for i in api_response.items:
        if not excluded_namespace(i.metadata.namespace):
            pass
        else:
            Secrets.append([i.metadata.name, i.metadata.namespace])
    return Secrets


def defined_config_map(v1, namespace=None):
    config_map = []
    try:
        if namespace is None:
            api_response = v1.list_config_map_for_all_namespaces()
        else:
            api_response = v1.list_namespaced_config_map(namespace=namespace)
    except Exception as err:
        print("Not able to reach Kubernetes cluster check Kubeconfig")
        raise err
    for i in api_response.items:
        if not excluded_namespace(i.metadata.namespace):
            config_map.append([i.metadata.name, i.metadata.namespace])
    return config_map


def defined_persistent_volume_claim(v1, namespace=None):
    PVC = []
    try:
        if namespace is None:
            api_response = v1.list_persistent_volume_claim_for_all_namespaces()
        else:
            api_response = v1.list_namespaced_persistent_volume_claim(
                namespace=namespace
            )
    except Exception as err:
        print("Not able to reach Kubernetes cluster check Kubeconfig")
        raise err
    for i in api_response.items:
        PVC.append([i.metadata.name, i.metadata.namespace])
    return PVC


def defined_service_account(v1, namespace=None):
    SA = []
    try:
        api_response = v1.list_namespaced_service_account(namespace=namespace)
    except Exception as err:
        print("Not able to reach Kubernetes cluster check Kubeconfig")
        raise err
    for i in api_response.items:
        if not excluded_namespace(i.metadata.namespace):
            pass
        else:
            SA.append([i.metadata.name, i.metadata.namespace])
    return SA


def defined_ingress(v1IngressApi, namespace=None):
    try:
        if namespace is None:
            api_response = v1IngressApi.list_ingress_for_all_namespaces()
        else:
            api_response = v1IngressApi.list_namespaced_ingress(namespace=namespace)
    except Exception as err:
        print("Not able to reach Kubernetes cluster check Kubeconfig")
        raise err
    for i in api_response.items:
        if not excluded_namespace(i.metadata.namespace):
            if i.spec.rules is not None:
                for rule in i.spec.rules:
                    if rule.http is not None:
                        if rule.http.paths is not None:
                            for path in rule.http.paths:
                                try:
                                    service_name = path.backend.service_name
                                except Exception:
                                    service_name = path.backend.service.name
                                INGRESS[i.metadata.name] = [
                                    service_name,
                                    i.metadata.namespace,
                                ]
    return INGRESS


def get_unused_ingress(endpoint, extra_svc):
    extra_ingress = []
    for key, value in INGRESS.items():
        if value not in endpoint or value in extra_svc:
            extra_ingress.append([key, value[1]])
    INGRESS.clear()
    return extra_ingress


def defined_role_binding(RbacAuthorizationV1Api, namespace=None):
    try:
        if namespace is None:
            api_response = RbacAuthorizationV1Api.list_role_binding_for_all_namespaces()
        else:
            api_response = RbacAuthorizationV1Api.list_namespaced_role_binding(
                namespace=namespace
            )
    except Exception as err:
        print("Not able to reach Kubernetes cluster check Kubeconfig")
        raise err
    for i in api_response.items:
        if not excluded_namespace(i.metadata.namespace):
            for sub in i.subjects:
                if "ServiceAccount" in sub.kind:
                    ROLE_BINDING[i.metadata.name] = [sub.name, i.metadata.namespace]
    return ROLE_BINDING


def get_unused_rb(SA, ExtraSA):
    extra_role_binding = []
    for i, j in ROLE_BINDING.items():
        if j not in SA or j in ExtraSA:
            extra_role_binding.append([i, j[1]])
    ROLE_BINDING.clear()
    return extra_role_binding


def get_unused_deployment(AppsV1Api, namespace=None):
    extra_deployments = []
    try:
        if namespace is None:
            api_response = AppsV1Api.list_deployment_for_all_namespaces()
        else:
            api_response = AppsV1Api.list_namespaced_deployment(namespace=namespace)
    except Exception as err:
        print("Not able to reach Kubernetes cluster check Kubeconfig")
        raise err
    for i in api_response.items:
        if not excluded_namespace(i.metadata.namespace):
            if i.spec.replicas == 0:
                extra_deployments.append([i.metadata.name, i.metadata.namespace])
    return extra_deployments


def get_unused_sts(AppsV1Api, namespace=None):
    ExtraSTS = []
    try:
        if namespace is None:
            api_response = AppsV1Api.list_stateful_set_for_all_namespaces()
        else:
            api_response = AppsV1Api.list_namespaced_stateful_set(namespace=namespace)
    except Exception as err:
        print("Not able to reach Kubernetes cluster check Kubeconfig")
        raise err
    for i in api_response.items:
        if not excluded_namespace(i.metadata.namespace):
            if i.spec.replicas == 0:
                ExtraSTS.append([i.metadata.name, i.metadata.namespace])
    return ExtraSTS


if __name__ == "__main__":
    print("\nThis script is created to find unused resource in Kubernetes\n")
    parser = argparse.ArgumentParser(description="Parser to get delete value")
    parser.add_argument(
        "-t",
        "--type",
        help="If need to run as services pass type as svc",
        required=False,
    )
    parser.add_argument(
        "--namespace",
        help="Only scan resources in this namespace",
        required=False,
    )
    args = parser.parse_args()
    if args.type == "svc":
        start_http_server(8000)
        while True:
            main("svc")
    else:
        main("standalone", namespace=args.namespace)
