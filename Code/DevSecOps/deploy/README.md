# Deployment demonstration

The main branch workflow builds and scans the fixed local image, enforces g1 and g2, then starts that same image as an **ephemeral container on the GitHub-hosted runner**. It checks `http://127.0.0.1:5000/health`, captures the container log and `deployment.json`, and stops the container. The deployment step is skipped automatically when either blocking gate fails.

This demonstrates the release ordering and a post-deploy health check without AWS, ECR, OIDC, or a persistent public service. The runner is discarded after the job, so this is not a production deployment. The evidence is uploaded in the `main-security-scan-evidence` artifact under `Code/DevSecOps/tests/results/deploy/`.

Do not apply the seeded Terraform configuration or deploy the vulnerable baseline image to an external environment.
