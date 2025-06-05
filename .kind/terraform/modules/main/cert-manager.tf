resource "kubernetes_namespace" "cert_manager" {
  metadata {
    name = "cert-manager"
  }
}


resource "kubectl_manifest" "cert_manager_helmrepository" {
  yaml_body          = file("${path.module}/flux2-manifests/cert-manager-helmrepository.yaml")
  override_namespace = kubernetes_namespace.flux_system.metadata[0].name
  depends_on         = [helm_release.flux_instance]
}

resource "kubectl_manifest" "cert_manager" {
  yaml_body          = file("${path.module}/flux2-manifests/cert-manager-helmrelease.yaml")
  override_namespace = kubernetes_namespace.cert_manager.metadata[0].name
  depends_on         = [kubectl_manifest.cert_manager_helmrepository]
  wait_for {
    field {
      key   = "status.conditions.[0].status"
      value = "True"
    }
  }
}
