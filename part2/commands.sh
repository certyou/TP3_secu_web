podman pull quay.io/keycloak/keycloak:22.0.3
podman run --name keycloak_dev -p 8180:8180 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:22.0.3 start-dev --http-port=8180
