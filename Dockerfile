# endoflife.ai MCP server - container image on Red Hat Universal Base Image.
#
# Runs the same handler that serves mcp.endoflife.ai (src/index.js) inside a
# Node.js process (server.mjs) so it can be deployed on a cluster, e.g. from
# the OpenShift AI MCP catalog. No build step, no dependencies: the server is
# plain ESM and talks to https://api.endoflife.ai over HTTPS.
#
#   docker build -t endoflife-mcp mcp-server/
#   docker run --rm -p 8080:8080 endoflife-mcp
#   curl -s localhost:8080/health
#
# The image runs as the unprivileged UBI default user (uid 1001) and needs no
# writable filesystem beyond /tmp. Egress: api.endoflife.ai:443 only.
FROM registry.access.redhat.com/ubi9/nodejs-22-minimal:latest

ARG VERSION=1.3.0
LABEL name="endoflife-ai/mcp-server" \
      vendor="EndofLife AI Inc." \
      version="${VERSION}" \
      release="1" \
      maintainer="partners@endoflife.ai" \
      summary="endoflife.ai MCP server: verified end-of-life dates, risk scores, KEV exposure and SBOM checks for 500+ products" \
      description="Model Context Protocol server exposing ten tools (check_eol, get_risk_score, scan_stack, list_products, get_product_lifecycle, get_kev_exposure, get_upcoming_eol, get_edge_device_status, get_upgrade_path, check_sbom) over Streamable HTTP. Every date it returns carries its source and verification time." \
      url="https://endoflife.ai/mcp" \
      io.k8s.display-name="endoflife.ai MCP server" \
      io.k8s.description="Software lifecycle intelligence for AI agents - end-of-life dates with provenance, EOL Risk Score, CISA KEV exposure, SBOM checks." \
      io.openshift.tags="mcp,model-context-protocol,eol,end-of-life,sbom,kev,lifecycle" \
      io.openshift.expose-services="8080:http"

ENV PORT=8080 \
    NODE_ENV=production \
    NPM_CONFIG_UPDATE_NOTIFIER=false

WORKDIR /opt/app-root/src
COPY --chown=1001:0 LICENSE /licenses/LICENSE
COPY --chown=1001:0 package.json server.json stdio.js server.mjs ./
COPY --chown=1001:0 src ./src

EXPOSE 8080
USER 1001
CMD ["node", "server.mjs"]
