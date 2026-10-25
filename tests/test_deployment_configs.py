"""
tests/test_deployment_configs.py
Automated static verification test suite for Docker, Docker Compose,
and Kubernetes HPA deployment configurations.
"""

from pathlib import Path
import yaml
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_dockerfile_configuration():
    """Verify production Dockerfile structure, non-root user, and healthcheck."""
    dockerfile_path = PROJECT_ROOT / "Dockerfile"
    assert dockerfile_path.exists(), "Dockerfile must exist at project root"

    content = dockerfile_path.read_text(encoding="utf-8")
    assert "FROM python:3.11-slim" in content, "Dockerfile should use python:3.11-slim base image"
    assert "WORKDIR /app" in content, "Working directory must be /app"
    assert "requirements.txt" in content, "Dependencies must be installed from requirements.txt"
    assert "spacy download en_core_web_sm" in content, "spaCy model must be downloaded for Presidio"
    assert "USER appuser" in content, "Dockerfile must enforce a non-root application user"
    assert "EXPOSE 8081" in content, "Container port 8081 must be exposed"
    assert "HEALTHCHECK" in content, "Container must have a HEALTHCHECK instruction"
    assert "CMD [\"uvicorn\", \"app.main:app\", \"--host\", \"0.0.0.0\", \"--port\", \"8081\"]" in content, (
        "FastAPI must be started with Uvicorn on 0.0.0.0:8081"
    )


def test_dockerignore_configuration():
    """Verify that .dockerignore excludes virtualenvs, caches, logs, secrets, and installers."""
    dockerignore_path = PROJECT_ROOT / ".dockerignore"
    assert dockerignore_path.exists(), ".dockerignore must exist at project root"

    content = dockerignore_path.read_text(encoding="utf-8")
    lines = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")]

    required_patterns = [".git", ".env", "venv/", "__pycache__/", "*.exe", "tests/"]
    for pattern in required_patterns:
        assert pattern in lines or any(p in pattern for p in lines), f"{pattern} must be ignored in .dockerignore"


def test_gitignore_configuration():
    """Verify that .gitignore excludes virtualenvs, secrets, cache, logs, and installer binaries."""
    gitignore_path = PROJECT_ROOT / ".gitignore"
    assert gitignore_path.exists(), ".gitignore must exist at project root"

    content = gitignore_path.read_text(encoding="utf-8")
    assert ".env" in content, ".env must be ignored in .gitignore"
    assert "venv/" in content, "venv/ must be ignored in .gitignore"
    assert "*.exe" in content or "Docker Desktop Installer.exe" in content, "Executables must be in .gitignore"
    assert "*.log" in content or "logs/" in content, "Logs must be in .gitignore"


def test_docker_compose_configuration():
    """Verify docker-compose.yml services, networking, volumes, and healthchecks."""
    compose_path = PROJECT_ROOT / "docker-compose.yml"
    assert compose_path.exists(), "docker-compose.yml must exist"

    with open(compose_path, "r", encoding="utf-8") as f:
        compose_data = yaml.safe_load(f)

    assert "services" in compose_data, "services key required in docker-compose.yml"
    services = compose_data["services"]

    # Gateway service
    assert "gateway" in services, "gateway service must be defined"
    gateway = services["gateway"]
    assert gateway["build"]["dockerfile"] == "Dockerfile"
    assert "8081:8081" in gateway["ports"]
    assert "postgres" in gateway["depends_on"]
    assert "redis" in gateway["depends_on"]
    assert "healthcheck" in gateway

    # PostgreSQL service
    assert "postgres" in services, "postgres service must be defined"
    postgres = services["postgres"]
    assert "postgres:15-alpine" in postgres["image"]
    assert "healthcheck" in postgres
    assert any("postgres_data" in v for v in postgres.get("volumes", []))

    # Redis service
    assert "redis" in services, "redis service must be defined"
    redis_svc = services["redis"]
    assert "redis:7-alpine" in redis_svc["image"]
    assert "healthcheck" in redis_svc
    assert any("redis_data" in v for v in redis_svc.get("volumes", []))

    # Volumes and networks
    assert "volumes" in compose_data
    assert "postgres_data" in compose_data["volumes"]
    assert "redis_data" in compose_data["volumes"]
    assert "networks" in compose_data
    assert "gateway_network" in compose_data["networks"]


def test_k8s_manifests_directory():
    """Verify that all required Kubernetes manifests exist in k8s/."""
    k8s_dir = PROJECT_ROOT / "k8s"
    assert k8s_dir.exists() and k8s_dir.is_dir(), "k8s/ directory must exist"

    expected_files = [
        "namespace.yaml",
        "configmap.yaml",
        "secret.yaml",
        "deployment.yaml",
        "service.yaml",
        "hpa.yaml",
        "postgres.yaml",
        "redis.yaml",
    ]
    for filename in expected_files:
        assert (k8s_dir / filename).exists(), f"k8s/{filename} must exist"


def test_k8s_deployment():
    """Verify Kubernetes Deployment manifest specification and security hardening."""
    dep_path = PROJECT_ROOT / "k8s" / "deployment.yaml"
    with open(dep_path, "r", encoding="utf-8") as f:
        dep = yaml.safe_load(f)

    assert dep["apiVersion"] == "apps/v1"
    assert dep["kind"] == "Deployment"
    assert dep["metadata"]["name"] == "gateway-deployment"
    assert dep["metadata"]["namespace"] == "zaalima-gateway"

    spec = dep["spec"]
    assert spec["replicas"] >= 2, "Deployment should specify at least 2 replicas"
    match_labels = spec["selector"]["matchLabels"]
    assert match_labels.get("app") == "security-gateway"

    pod_spec = spec["template"]["spec"]
    # Pod Security Context
    assert "securityContext" in pod_spec
    assert pod_spec["securityContext"].get("runAsNonRoot") is True
    assert pod_spec["securityContext"].get("runAsUser") == 10001

    containers = pod_spec["containers"]
    assert len(containers) >= 1
    gateway_container = containers[0]
    assert gateway_container["name"] == "security-gateway"

    # Container Security Context
    assert "securityContext" in gateway_container
    assert gateway_container["securityContext"].get("allowPrivilegeEscalation") is False

    # Port
    ports = gateway_container.get("ports", [])
    assert any(p.get("containerPort") == 8081 for p in ports)

    # Resource requests and limits
    resources = gateway_container.get("resources", {})
    assert "requests" in resources and "cpu" in resources["requests"] and "memory" in resources["requests"]
    assert "limits" in resources and "cpu" in resources["limits"] and "memory" in resources["limits"]

    # Probes
    assert "livenessProbe" in gateway_container
    assert gateway_container["livenessProbe"]["httpGet"]["path"] == "/health"
    assert "readinessProbe" in gateway_container
    assert gateway_container["readinessProbe"]["httpGet"]["path"] == "/health/readiness"


def test_k8s_service():
    """Verify Kubernetes Service manifest routing to container port 8081."""
    svc_path = PROJECT_ROOT / "k8s" / "service.yaml"
    with open(svc_path, "r", encoding="utf-8") as f:
        svc = yaml.safe_load(f)

    assert svc["apiVersion"] == "v1"
    assert svc["kind"] == "Service"
    assert svc["metadata"]["name"] == "gateway-service"
    assert svc["metadata"]["namespace"] == "zaalima-gateway"
    assert svc["spec"]["type"] == "ClusterIP"
    assert svc["spec"]["selector"].get("app") == "security-gateway"

    ports = svc["spec"]["ports"]
    assert any(p.get("port") == 8081 and p.get("targetPort") == 8081 for p in ports)


def test_k8s_hpa():
    """Verify Kubernetes HPA using autoscaling/v2 with CPU target and scaling policies."""
    hpa_path = PROJECT_ROOT / "k8s" / "hpa.yaml"
    with open(hpa_path, "r", encoding="utf-8") as f:
        hpa = yaml.safe_load(f)

    assert hpa["apiVersion"] == "autoscaling/v2", "HPA must use autoscaling/v2"
    assert hpa["kind"] == "HorizontalPodAutoscaler"
    assert hpa["metadata"]["name"] == "gateway-hpa"
    assert hpa["metadata"]["namespace"] == "zaalima-gateway"

    spec = hpa["spec"]
    assert spec["scaleTargetRef"]["kind"] == "Deployment"
    assert spec["scaleTargetRef"]["name"] == "gateway-deployment"
    assert spec["minReplicas"] == 2
    assert spec["maxReplicas"] == 5

    # Resource metrics
    metrics = spec.get("metrics", [])
    cpu_metric = next((m for m in metrics if m.get("resource", {}).get("name") == "cpu"), None)
    assert cpu_metric is not None, "CPU metric must be specified"
    assert cpu_metric["resource"]["target"]["averageUtilization"] == 70

    # Scaling behavior
    assert "behavior" in spec
    assert "scaleUp" in spec["behavior"]
    assert "scaleDown" in spec["behavior"]
    assert spec["behavior"]["scaleDown"].get("stabilizationWindowSeconds") == 300


def test_k8s_postgres_and_redis():
    """Verify Kubernetes PostgreSQL and Redis manifests have PVCs and Services."""
    pg_path = PROJECT_ROOT / "k8s" / "postgres.yaml"
    with open(pg_path, "r", encoding="utf-8") as f:
        pg_docs = list(yaml.safe_load_all(f))
    kinds = [doc["kind"] for doc in pg_docs if doc]
    assert "PersistentVolumeClaim" in kinds
    assert "Deployment" in kinds
    assert "Service" in kinds

    redis_path = PROJECT_ROOT / "k8s" / "redis.yaml"
    with open(redis_path, "r", encoding="utf-8") as f:
        redis_docs = list(yaml.safe_load_all(f))
    redis_kinds = [doc["kind"] for doc in redis_docs if doc]
    assert "PersistentVolumeClaim" in redis_kinds
    assert "Deployment" in redis_kinds
    assert "Service" in redis_kinds
