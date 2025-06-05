# kind_cluster module: Provisions the Kind cluster

terraform {
  required_version = ">= 1.0.0"
  required_providers {

    kind = {
      source  = "tehcyx/kind"
      version = "0.9.0"
    }
  }
}


resource "kind_cluster" "default" {
  name = var.name
  kind_config {
    kind        = "Cluster"
    api_version = "kind.x-k8s.io/v1alpha4"
    containerd_config_patches = [<<EOT
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localhost:5000"]
    endpoint = ["http://kind-registry:5000"]
EOT
    ]
    node {
      role = "control-plane"
      labels = {
        "topology.kubernetes.io/zone" = "az-1"
      }
    }
    node {
      role = "worker"
      labels = {
        "topology.kubernetes.io/zone" = "az-1"
      }
    }
    node {
      role = "worker"
      labels = {
        "topology.kubernetes.io/zone" = "az-2"
      }
    }
    node {
      role = "worker"
      labels = {
        "topology.kubernetes.io/zone" = "az-3"
      }
    }
  }
}
